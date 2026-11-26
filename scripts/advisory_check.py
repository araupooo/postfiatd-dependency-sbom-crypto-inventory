#!/usr/bin/env python3
"""Match pinned dependency versions against public advisories (two-pass method).

PASS 1 -- OSV version queries (curl, not urllib: this VM's egress proxy drops
Python urllib connections; curl works). Queries api.osv.dev/v1/query for every
pinned package version (Conan ecosystem) and for the vendored upstreams via
pkg:github purls. Results are saved verbatim. MEASURED LIMITATION (2026-11-26):
these version queries return 0 results for C/C++ libraries whose advisories
are recorded as GIT commit ranges with no version/ecosystem data. Controls
prove it: OSV purl queries for c-ares 1.26.0 (known CVE-2024-25629) and
sqlite 3.48.0 (known CVE-2025-3277) both return 0, while npm/PyPI controls
(lodash 4.17.20 -> 4 vulns, requests 2.28.0 -> 8 vulns) work. A 0 from pass 1
is therefore NOT evidence that a version is clean.

PASS 2 -- targeted record fetch + curated triage. For every CVE/GHSA that the
manual triage (web + NVD API + distro changelogs, 2026-11-26) found relevant,
the OSV record is fetched by ID (api.osv.dev/v1/vulns/<id>) and saved under
outputs/osv-records/. Applicability (affected / not-affected / not-applicable),
fixed version, CVSS 3.1 score (recomputed from the vector in-script) and
reachability against the pinned tree are recorded per finding from primary
sources (NVD API, Debian/Ubuntu/SUSE changelogs, OSV GHSA records).

Rules:
  * Only versions pinned in the tree/graph are tested; the tested version is
    recorded on every finding.
  * A package with no advisory found is recorded as such, never as "clean".
  * Vendored unversioned code (ed25519-donna) cannot be version-matched and
    is recorded as not-queryable with the reason.
  * OSV aggregates GHSA/CVE/NVD records; advisory IDs link to osv.dev.

Usage: advisory_check.py --deps <dependencies.json> --graph <conan-graph-deps.json>
                          --raw-out <json> --findings-json <json> --findings-md <md>
                          --records-dir <dir> --controls-out <json>
"""
import argparse
import json
import math
import os
import subprocess
import sys

PIN = "0085a1ff885d6a446369cf73a4430f75af22be55"
REPO = "postfiatorg/postfiatd"
QUERY_DATE = "2026-11-26"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns"

# ---------------------------------------------------------------- curl helper
def curl_json(url, payload=None, timeout=30, retries=3):
    """POST (payload given) or GET via curl; returns (parsed_json, error_str)."""
    cmd = ["curl", "-sS", "--max-time", str(timeout), "--retry", str(retries),
           "--retry-all-errors", "--retry-delay", "2"]
    if payload is not None:
        cmd += ["-X", "POST", "-H", "Content-Type: application/json",
                "-d", json.dumps(payload)]
    cmd.append(url)
    for attempt in range(retries + 1):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                return json.loads(proc.stdout), None
            except json.JSONDecodeError as e:
                return None, "json-parse-error: %s" % e
        err = (proc.stderr or "").strip() or "empty response (exit %d)" % proc.returncode
        if attempt == retries:
            return None, err
    return None, "unreachable"


# ------------------------------------------------------- CVSS 3.1 calculator
def _roundup(v):
    """FIRST reference Roundup: smallest 1-decimal number >= input."""
    int_input = int(round(v * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31_base(vector):
    """Return (score, severity) computed from a CVSS:3.1 vector string."""
    parts = vector.split("/")
    m = {}
    for kv in parts[1:]:
        k, _, val = kv.partition(":")
        m[k] = val
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    changed = m["S"] == "C"
    pr = ({"N": 0.85, "L": 0.68, "H": 0.50} if changed
          else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss * 0.9731 - 0.02) ** 13)
    else:
        impact = 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0, "None"
    base = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
    score = _roundup(base)
    sev = ("None" if score == 0 else "Low" if score < 4 else
           "Medium" if score < 7 else "High" if score < 9 else "Critical")
    return score, sev


# ------------------------------------------------- curated triage (2026-11-26)
# status: affected | not_affected | not_applicable | support_status
# reachability: network | latent | not_reachable | transitive-unverified | n/a
FINDINGS = [
    {
        "id": "CVE-2025-0838", "osv_ids": ["CVE-2025-0838"],
        "package": "abseil", "pinned_version": "20230802.1",
        "status": "affected", "title": "Heap buffer overflow in absl hash containers",
        "cvss31_score": 9.8, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss31_severity": "Critical",
        "cvss40_note": "CNA (Google) CVSS 4.0 score is 5.9 Medium "
            "(CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/...); NVD CVSS 3.1 is 9.8 Critical. "
            "This register ranks on NVD CVSS 3.1, as for all other findings.",
        "fixed_version": "20230802.3 (SUSE-SU-2026:20268-1) / 20250127.0",
        "fixed_version_source": "SUSE backported fix commit 5a0e2cb5 to the "
            "20230802 line as 20230802.3; upstream fix commit 5a0e2cb5e3958dd90bb8569a2766622cb74d90c1 "
            "is in release 20250127.0.",
        "reachability": "transitive-unverified",
        "reachability_text": "AFFECTED VERSION. The flaw needs a caller to pass a "
            "huge size to the sized constructors / reserve() / rehash() of "
            "absl::{flat,node}hash{set,map}. Zero direct uses of absl::flat_hash* "
            "in postfiatd src/ and include/ (grep, pinned tree). abseil is used "
            "transitively by grpc; no attacker-controlled size argument was "
            "identified in grpc's internal use. Network reachability not demonstrated.",
        "description": "Sized constructors, reserve() and rehash() of "
            "absl::{flat,node}hash{set,map} did not impose an upper bound on their "
            "size argument; a very large size causes an integer overflow when "
            "computing the container backing-store size and a subsequent "
            "out-of-bounds memory write.",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2025-0838"},
            {"label": "NVD", "url": "https://nvd.nist.gov/vuln/detail/cve-2025-0838"},
            {"label": "Ubuntu CVE-2025-0838 (fixed 20230802.1-4.2ubuntu0.2)",
             "url": "https://ubuntu.com/security/CVE-2025-0838"},
            {"label": "Fix commit 5a0e2cb5",
             "url": "https://github.com/abseil/abseil-cpp/commit/5a0e2cb5e3958dd90bb8569a2766622cb74d90c1"},
        ],
    },
    {
        "id": "CVE-2023-44487", "osv_ids": ["CVE-2023-44487"],
        "package": "grpc", "pinned_version": "1.50.1",
        "status": "affected", "title": "HTTP/2 Rapid Reset (CISA KEV, exploited in the wild)",
        "cvss31_score": 7.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss31_severity": "High",
        "fixed_version": "1.59.2",
        "fixed_version_source": "SUSE-SU-2024:0573-1: fixed in grpc 1.59.2; "
            "OSV GIT range [0, fix commit 06021d91).",
        "reachability": "network",
        "reachability_text": "REACHABLE via the gRPC service. postfiatd's gRPC "
            "server is an HTTP/2 server (src/xrpld/app/main/GRPCServer.cpp:571-572, "
            "InsecureServerCredentials). Shipped configs bind [port_grpc] port 50051 "
            "on 127.0.0.1 (cfg/postfiatd-example.cfg:1466-1468); the bind address is "
            "operator-configurable, so exposure becomes remote if bound publicly. "
            "A remote unauthenticated attacker that can reach the endpoint can "
            "exhaust server resources with RST_STREAM floods.",
        "description": "HTTP/2 Rapid Reset: a peer can send RST_STREAM frames "
            "immediately after requests, causing the server to do work that is "
            "then cancelled, enabling unauthenticated denial of service. Listed in "
            "CISA Known Exploited Vulnerabilities; exploited in the wild Aug-Oct 2023.",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2023-44487"},
        ],
    },
    {
        "id": "CVE-2023-33953", "osv_ids": ["CVE-2023-33953", "GHSA-496j-2rq6-j6cc"],
        "package": "grpc", "pinned_version": "1.50.1",
        "status": "affected", "title": "HPACK table accounting error allows DoS via unwanted disconnects",
        "cvss31_score": 7.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss31_severity": "High",
        "fixed_version": "1.53.2",
        "fixed_version_source": "GHSA-496j-2rq6-j6cc ECOSYSTEM range starts at 0, "
            "fixed in 1.53.2 (pre-1.53 line).",
        "reachability": "network",
        "reachability_text": "REACHABLE via the gRPC service (same endpoint as "
            "CVE-2023-44487): errors in HPACK table accounting cause unwanted "
            "disconnects between clients and servers; a remote peer can trigger it "
            "with crafted HEADERS frames.",
        "description": "Errors in HPACK table accounting in gRPC C-core can lead "
            "to unwanted disconnects between clients and servers (denial of service).",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2023-33953"},
            {"label": "OSV GHSA record", "url": "https://osv.dev/vulnerability/GHSA-496j-2rq6-j6cc"},
        ],
    },
    {
        "id": "CVE-2026-4111", "osv_ids": ["CVE-2026-4111"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "RAR5 infinite-loop denial of service",
        "cvss31_score": 7.5, "cvss31_vector": None,
        "cvss31_severity": "High",
        "cvss31_note": "Vector not present in the fetched OSV record; score 7.5 as "
            "published (OpenCVE/NVD).",
        "fixed_version": "3.8.6",
        "fixed_version_source": "Debian libarchive (3.8.6-1) changelog: 'Fix "
            "CVE-2026-4111'; Yocto: 'fixed since 3.8.6'; SUSE 3.8.6 changelog: "
            "'RAR5 reader: fix infinite loop in rar5 decompression'.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use. The only libarchive "
            "consumer in the tree is extractTarLz4 (src/libxrpl/basics/Archive.cpp:36-116), "
            "which enables ONLY archive_read_support_format_tar + lz4 filter. The RAR5 "
            "reader is never enabled.",
        "description": "Logical deadlock between the RAR5 filter subsystem and the "
            "half-window output limiter leads to an infinite loop (DoS) on a crafted RAR5 archive.",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2026-4111"},
            {"label": "Debian libarchive changelog (3.8.6 fixes 4111)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-4424", "osv_ids": ["CVE-2026-4424"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "RAR heap out-of-bounds read (LZSS window)",
        "cvss31_score": 7.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss31_severity": "High",
        "fixed_version": "3.8.7",
        "fixed_version_source": "Debian libarchive (3.8.7-1) changelog: 'Fix "
            "CVE-2026-4424'; Yocto: 'fixed since 3.8.7'; SUSE 3.8.1 spec applies "
            "CVE-2026-4424.patch (3.8.1 affected).",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use: RAR reader never "
            "enabled (Archive.cpp enables tar only).",
        "description": "Heap out-of-bounds read in the RAR archive processing "
            "logic due to improperly sized LZSS windows (archive_read_support_format_rar.c).",
        "evidence": [
            {"label": "NVD CVE-2026-4424 (CVSS 3.1 7.5, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-4424"},
            {"label": "Debian libarchive changelog (3.8.7 fixes 4424)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-5121", "osv_ids": ["CVE-2026-5121"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "zisofs block-pointer integer overflow (32-bit only)",
        "cvss31_score": 7.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss31_severity": "High",
        "fixed_version": "3.8.7",
        "fixed_version_source": "Debian libarchive (3.8.7-1) changelog: 'Fix "
            "CVE-2026-5121'; Yocto: 'fixed since 3.8.7'.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use on two counts: the "
            "zisofs decompression code lives in the ISO9660 format reader "
            "(archive_read_support_format_iso9660.c), which Archive.cpp never "
            "enables; and the flaw triggers only on 32-bit systems, while the "
            "Dockerfile builds on 64-bit ubuntu:24.04.",
        "description": "On 32-bit systems, an integer overflow in the zisofs "
            "block pointer allocation allows a heap overflow via a crafted ISO image.",
        "evidence": [
            {"label": "NVD CVE-2026-5121 (CVSS 3.1 7.5, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5121"},
            {"label": "Debian libarchive changelog (3.8.7 fixes 5121)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-14164", "osv_ids": ["CVE-2026-14164"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "RAR5 reader double free",
        "cvss31_score": 7.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss31_severity": "High",
        "fixed_version": "3.8.8",
        "fixed_version_source": "Debian libarchive (3.8.8-1) changelog: 'Fix "
            "CVE-2026-14164'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to "
            "archive_read_support_format_rar5.c.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use: RAR5 reader never "
            "enabled (Archive.cpp enables tar only).",
        "description": "Double free in libarchive's RAR5 reader during parsing of "
            "a specially crafted RAR5 archive (dangling pointers in init_unpack).",
        "evidence": [
            {"label": "NVD CVE-2026-14164 (CVSS 3.1 7.5, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-14164"},
            {"label": "Debian libarchive changelog (3.8.8 fixes 14164)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-4426", "osv_ids": ["CVE-2026-4426"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "zisofs decompression undefined behaviour",
        "cvss31_score": 6.5, "cvss31_vector":
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
        "cvss31_severity": "Medium",
        "fixed_version": "3.8.7",
        "fixed_version_source": "Debian libarchive (3.8.7-1) changelog: 'Fix "
            "CVE-2026-4426'; Yocto: 'fixed since 3.8.7'; SUSE 3.8.1 spec applies "
            "CVE-2026-4426.patch.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use: zisofs code lives "
            "in the ISO9660 format reader, never enabled by Archive.cpp.",
        "description": "Undefined behaviour due to an unvalidated operand in a "
            "shift expression of the zisofs decompression code.",
        "evidence": [
            {"label": "NVD CVE-2026-4426 (CVSS 3.1 6.5, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-4426"},
            {"label": "Debian libarchive changelog (3.8.7 fixes 4426)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-5745", "osv_ids": ["CVE-2026-5745"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "NULL pointer dereference in ACL text parsing",
        "cvss31_score": 5.5, "cvss31_vector":
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
        "cvss31_severity": "Medium",
        "fixed_version": "3.8.8",
        "fixed_version_source": "Debian libarchive (3.8.8-1) changelog: 'Fix "
            "CVE-2026-5745'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to "
            "archive_acl.c (archive_acl_from_text_nl).",
        "reachability": "latent",
        "reachability_text": "LATENT tar-path flaw. The vulnerable function "
            "archive_acl_from_text_nl() parses ACL text from tar PAX extended "
            "headers, and Archive.cpp enables tar reading with ARCHIVE_EXTRACT_ACL "
            "(Archive.cpp:75-77). BUT extractTarLz4 is the only function in "
            "Archive.cpp and has NO caller in src/ or include/ in the pinned tree "
            "(grep, 2026-11-26), so the code path is present in libxrpl source with "
            "no in-tree execution path in xrpld as pinned. Reachable only if the "
            "utility is invoked by downstream tooling or future code.",
        "description": "NULL pointer dereference in the ACL parsing logic "
            "(archive_acl_from_text_nl) when processing a malformed ACL string in "
            "a tar archive.",
        "evidence": [
            {"label": "NVD CVE-2026-5745 (CVSS 3.1 5.5, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5745"},
            {"label": "Debian libarchive changelog (3.8.8 fixes 5745)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-15028", "osv_ids": ["CVE-2026-15028"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "Heap overflow parsing tar PAX SUN.holesdata sparse attribute",
        "cvss31_score": 3.9, "cvss31_vector":
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:L",
        "cvss31_severity": "Low",
        "fixed_version": "3.8.9",
        "fixed_version_source": "Debian libarchive (3.8.9-1) changelog: 'Fix "
            "CVE-2026-15028'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to "
            "archive_read_support_format_tar.c (1-byte OOB read).",
        "reachability": "latent",
        "reachability_text": "LATENT tar-path flaw. The vulnerable code is the tar "
            "reader's PAX extended-header parsing, which Archive.cpp enables "
            "(format tar). BUT extractTarLz4 has NO caller in src/ or include/ in "
            "the pinned tree, so the code path is present in libxrpl source with no "
            "in-tree execution path in xrpld as pinned. Reachable only if the "
            "utility is invoked; the input would then be an operator-supplied local "
            "tar file (CVSS AV:L/UI:R matches: local access + user interaction).",
        "description": "A remote attacker can trigger a heap overflow by providing "
            "a specially crafted tar archive; the issue occurs during parsing of a "
            "PAX extended header containing a malformed SUN.holesdata sparse-file "
            "attribute (CWE-805/CWE-122).",
        "evidence": [
            {"label": "NVD CVE-2026-15028 (CVSS 3.1 3.9, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-15028"},
            {"label": "Debian libarchive changelog (3.8.9 fixes 15028)",
             "url": "https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog"},
        ],
    },
    {
        "id": "CVE-2026-16517", "osv_ids": ["CVE-2026-16517"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "Signed integer overflow in ZIP writer (encrypted entries)",
        "cvss31_score": 2.9, "cvss31_vector":
            "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cvss31_severity": "Low",
        "fixed_version": "3.8.9",
        "fixed_version_source": "Debian libarchive (3.8.9-1) changelog: 'Fix "
            "CVE-2026-16517'; Ubuntu 3.8.5-1ubuntu2.3: integer overflow in ZIP writer.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use: the flaw is in "
            "the ZIP writer (archive_write_set_format_zip.c) with ZIP encryption "
            "enabled. Archive.cpp uses archive_write_disk only; it never writes zip.",
        "description": "Signed integer overflow in archive_write_zip_header when "
            "ZIP encryption is enabled and the entry filename is crafted.",
        "evidence": [
            {"label": "NVD CVE-2026-16517 (CVSS 3.1 2.9, vector as recorded)",
             "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-16517"},
            {"label": "Ubuntu libarchive changelog (3.8.5-1ubuntu2.3, CVE-2026-16517)",
             "url": "https://changelogs.ubuntu.com/changelogs/pool/main/liba/libarchive/libarchive_3.8.5-1ubuntu2.3/changelog"},
        ],
    },
    {
        "id": "CVE-2025-64031", "osv_ids": ["CVE-2025-64031", "GHSA-92wx-p669-8gr9"],
        "package": "libarchive", "pinned_version": "3.8.1",
        "status": "affected", "title": "strcpy heap overflow in gzip writer",
        "cvss31_score": 2.5, "cvss31_vector": None,
        "cvss31_severity": "Low",
        "cvss31_note": "Vector not present in the fetched OSV record; score 2.5 as "
            "published by GHSA-92wx-p669-8gr9.",
        "fixed_version": "3.8.2",
        "fixed_version_source": "GHSA-92wx-p669-8gr9: 'libarchive 3.8.x before "
            "3.8.2'; SUSE 3.8.2 changelog lists the gzip-writer fix.",
        "reachability": "not_reachable",
        "reachability_text": "NOT REACHABLE via postfiatd's use: the flaw is in the "
            "gzip writer. Archive.cpp writes with archive_write_disk only and "
            "enables only the lz4 read filter; it never writes gzip.",
        "description": "strcpy heap overflow in the gzip writer of libarchive 3.8.x.",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2025-64031"},
            {"label": "OSV GHSA record", "url": "https://osv.dev/vulnerability/GHSA-92wx-p669-8gr9"},
        ],
    },
    {
        "id": "OPENSSL-1.1.1-EOL", "osv_ids": [],
        "package": "openssl", "pinned_version": "1.1.1w",
        "status": "support_status",
        "title": "OpenSSL 1.1.1 end-of-life: no public security fixes since 2023-09-11",
        "cvss31_score": None, "cvss31_vector": None,
        "cvss31_severity": "High-equivalent (no CVSS; support-status finding)",
        "fixed_version": "Migrate to OpenSSL 3.x (3.5 LTS recommended)",
        "fixed_version_source": "OpenSSL project: 1.1.1 EOL 2023-09-11; 1.1.1w "
            "(2023-09-11) was the final 1.1.1 release.",
        "reachability": "n/a",
        "reachability_text": "Support-status finding, not a single CVE. 1.1.1w is "
            "the final 1.1.1 release; any vulnerability discovered in the 1.1.1 line "
            "after 2023-09-11 receives no public fix. The pinned tree also blocks "
            "migration: src/libxrpl/crypto/digest.cpp uses RIPEMD160 low-level APIs "
            "removed from the OpenSSL 3.x default provider, so an upgrade needs code "
            "changes, not just a version bump (see decision memo).",
        "description": "OpenSSL 1.1.1 reached end of life on 2023-09-11. The "
            "pinned version 1.1.1w is the last 1.1.1 release and receives no further "
            "public security fixes.",
        "evidence": [
            {"label": "OpenSSL 1.1.1 EOL reminder (2023-06-15)",
             "url": "https://www.openssl.org/blog/blog/2023/06/15/1.1.1-EOL/"},
        ],
    },
    {
        "id": "CVE-2026-11460", "osv_ids": ["CVE-2026-11460"],
        "package": "boost", "pinned_version": "1.83.0",
        "status": "not_applicable",
        "title": "Boost.Serialization type-confusion RCE (component not linked)",
        "cvss31_score": 7.3, "cvss31_vector": None,
        "cvss31_severity": "High",
        "cvss31_note": "Score 7.3 as published; vector not recorded in this triage.",
        "fixed_version": "None (no patch as of 2026-11-26)",
        "fixed_version_source": "Published 2026-06-07; PoC public since Oct 2025; "
            "affects Boost 1.0-1.91; no patch released.",
        "reachability": "n/a",
        "reachability_text": "NOT APPLICABLE. The flaw is in Boost.Serialization. "
            "postfiatd links these Boost components (conanfile.py / CMakeLists): "
            "chrono, container, coroutine, date_time, filesystem, json, "
            "program_options, regex, system, thread. Zero hits for "
            "boost::serialization / boost/archive in src/ and include/ (grep, "
            "pinned tree). The vulnerable component is not linked.",
        "description": "Type-confusion remote code execution in Boost.Serialization "
            "(deserialisation of untrusted data).",
        "evidence": [
            {"label": "OSV record", "url": "https://osv.dev/vulnerability/CVE-2026-11460"},
        ],
    },
]

NOT_AFFECTED = [
    {"id": "CVE-2023-1428", "package": "grpc", "pinned_version": "1.50.1",
     "reason": "Introduced in 1.51.0 (hpack table fix), fixed in 1.53.0. 1.50.1 predates the vulnerable code.",
     "evidence": "GHSA-2c4m-59x9-fr3g ECOSYSTEM range [1.51.0, 1.53.0)."},
    {"id": "CVE-2023-32731", "package": "grpc", "pinned_version": "1.50.1",
     "reason": "Introduced BY the CVE-2023-1428 fix commit 358bfb58 (in 1.53.0), fixed in 1.56.0. 1.50.1 predates both.",
     "evidence": "GHSA-7v5x-rpf4-c6xj."},
    {"id": "CVE-2023-32732", "package": "grpc", "pinned_version": "1.50.1",
     "reason": "Same introduction as CVE-2023-32731 (the 1428 fix), fixed in 1.53.1/1.54.2. 1.50.1 predates it.",
     "evidence": "GHSA-x3r6-5j9r-r2gq."},
    {"id": "CVE-2023-4785", "package": "grpc", "pinned_version": "1.50.1",
     "reason": "GHSA-p25m-jpj4-qcrr ECOSYSTEM ranges start at 1.53.0. The NVD text 'starting version 1.23' is an imprecise CPE approximation; the GHSA range is authoritative.",
     "evidence": "OSV record GHSA-p25m-jpj4-qcrr."},
    {"id": "CVE-2024-11407", "package": "grpc", "pinned_version": "1.50.1",
     "reason": "Transmit-zero-copy code introduced in v1.51.0-pre1; 1.50.1 predates it. Fixed in v1.68.0-pre1 (commit e9046b2b). Also requires GRPC_ARG_TCP_TX_ZEROCOPY_ENABLED, which postfiatd does not set.",
     "evidence": "Wiz CVE-2024-11407 analysis: https://www.wiz.io/vulnerability-database/cve/cve-2024-11407 ; Debian grpc tracker: https://tracker.debian.org/pkg/grpc"},
    {"id": "CVE-2025-5914", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version.",
     "evidence": "Upstream release notes / GHSA."},
    {"id": "CVE-2025-5915", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version.",
     "evidence": "Upstream release notes / GHSA."},
    {"id": "CVE-2025-5916", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version.",
     "evidence": "Upstream release notes / GHSA."},
    {"id": "CVE-2025-5917", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version.",
     "evidence": "Upstream release notes / GHSA."},
    {"id": "CVE-2025-5918", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version.",
     "evidence": "Upstream release notes / GHSA."},
    {"id": "CVE-2025-25724", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "NVD CPE range ends at 3.7.7 inclusive ('through 3.7.7'). 3.8.1 is outside the affected range.",
     "evidence": "NVD API record: cpe libarchive, versionEndIncluding 3.7.7."},
    {"id": "CVE-2025-60753", "package": "libarchive", "pinned_version": "3.8.1",
     "reason": "bsdtar-tool-only flaw, fixed in 3.8.1; the bsdtar CLI tool is not linked into postfiatd.",
     "evidence": "Upstream advisory."},
    {"id": "CVE-2025-3277", "package": "sqlite3", "pinned_version": "3.49.1",
     "reason": "Affects versions < 3.49.1; 3.49.1 IS the fix version.",
     "evidence": "SQLite forum / upstream changelog."},
    {"id": "CVE-2025-29087", "package": "sqlite3", "pinned_version": "3.49.1",
     "reason": "Fixed in 3.49.1.",
     "evidence": "Upstream changelog."},
    {"id": "CVE-2025-29088", "package": "sqlite3", "pinned_version": "3.49.1",
     "reason": "Fixed in 3.49.1.",
     "evidence": "Upstream changelog."},
    {"id": "CVE-2025-7458", "package": "sqlite3", "pinned_version": "3.49.1",
     "reason": "Affects 3.39.2-3.41.1 only. 3.49.1 is outside the range.",
     "evidence": "Upstream advisory."},
    {"id": "CVE-2024-7254", "package": "protobuf", "pinned_version": "3.21.12",
     "reason": "Protobuf Java Lite only; the pinned dependency is protobuf-cpp (C++). Not the affected product.",
     "evidence": "GHSA record (Java Lite)."},
    {"id": "CVE-2022-1941", "package": "protobuf", "pinned_version": "3.21.12",
     "reason": "protobuf-cpp affected through 3.21.5; 3.21.12 is newer than the fix.",
     "evidence": "GHSA record."},
    {"id": "CVE-2024-25629", "package": "c-ares", "pinned_version": "1.34.9",
     "reason": "Fixed in 1.27.0; 1.34.9 is newer than the fix.",
     "evidence": "c-ares security advisory."},
    {"id": "CVE-2023-31147", "package": "c-ares", "pinned_version": "1.34.9",
     "reason": "Fixed in 1.19.1; 1.34.9 is newer than the fix.",
     "evidence": "c-ares security advisory."},
    {"id": "CVE-2023-31130", "package": "c-ares", "pinned_version": "1.34.9",
     "reason": "Fixed in 1.19.1; 1.34.9 is newer than the fix.",
     "evidence": "c-ares security advisory."},
    {"id": "CVE-2023-32067", "package": "c-ares", "pinned_version": "1.34.9",
     "reason": "Fixed in 1.19.1; 1.34.9 is newer than the fix.",
     "evidence": "c-ares security advisory."},
    {"id": "CVE-2025-31498", "package": "c-ares", "pinned_version": "1.34.9",
     "reason": "Affects 1.32.3-1.34.4, fixed in 1.34.5; 1.34.9 is newer than the fix.",
     "evidence": "IBM security bulletin."},
    {"id": "CVE-2023-6129", "package": "openssl", "pinned_version": "1.1.1w",
     "reason": "Introduced in OpenSSL 3.2 (PowerPC code). The 1.1.1 line never contained the vulnerable code.",
     "evidence": "OpenSSL security advisory."},
    {"id": "CVE-2024-5535", "package": "openssl", "pinned_version": "1.1.1w",
     "reason": "Affects OpenSSL 3.0-3.3 only. The 1.1.1 line is outside the range.",
     "evidence": "OpenSSL security advisory."},
    {"id": "CVE-2023-6992", "package": "zlib", "pinned_version": "1.3.1",
     "reason": "This CVE is for the Cloudflare zlib fork, not zlib.net. The pinned dependency is zlib.net 1.3.1.",
     "evidence": "NVD record (Cloudflare zlib product)."},
    {"id": "CVE-2025-66566", "package": "lz4", "pinned_version": "1.10.0",
     "reason": "lz4-JAVA (yawkat) only; JNI-based implementations not affected. The pinned dependency is the C library lz4 1.10.0.",
     "evidence": "Ubuntu CVE-2025-66566: https://ubuntu.com/security/CVE-2025-66566"},
    {"id": "CVE-2024-36114", "package": "snappy", "pinned_version": "1.2.1",
     "reason": "aircompressor (Java) only. The pinned dependency is the C++ snappy library 1.2.1.",
     "evidence": "GHSA record (airlift aircompressor)."},
    {"id": "CVE-2024-36124", "package": "snappy", "pinned_version": "1.2.1",
     "reason": "iq80 Snappy (Java) only. The pinned dependency is the C++ snappy library 1.2.1.",
     "evidence": "GHSA record (iq80 snappy)."},
    {"id": "CVE-2026-71498", "package": "re2", "pinned_version": "20230301",
     "reason": "node-re2 (npm wrapper) only; out-of-bounds read with malformed UTF-8 in the Node.js binding. The pinned dependency is the C++ re2 library.",
     "evidence": "OX Radar re2 (npm) advisory list."},
    {"id": "CVE-2026-71430", "package": "re2", "pinned_version": "20230301",
     "reason": "node-re2 (npm wrapper) only. Not the C++ re2 library.",
     "evidence": "OX Radar re2 (npm) advisory list."},
    {"id": "CVE-2026-68499", "package": "re2", "pinned_version": "20230301",
     "reason": "node-re2 (npm wrapper) only. Not the C++ re2 library.",
     "evidence": "OX Radar re2 (npm) advisory list."},
    {"id": "CVE-2026-67550", "package": "re2", "pinned_version": "20230301",
     "reason": "node-re2 (npm wrapper) only. Not the C++ re2 library.",
     "evidence": "OX Radar re2 (npm) advisory list."},
    {"id": "CVE-2026-107853", "package": "secp256k1", "pinned_version": "0.6.0",
     "reason": "tiny-secp256k1 (JavaScript wrapper) only. Not bitcoin-core/secp256k1 (C library).",
     "evidence": "OSV / GHSA record (npm package)."},
    {"id": "CVE-2026-63410", "package": "secp256k1", "pinned_version": "0.6.0",
     "reason": "secp256k1-native (Ruby wrapper) only. Not bitcoin-core/secp256k1 (C library).",
     "evidence": "OSV / GHSA record (Ruby gem)."},
]

# Packages where the triage found no public advisory for the pinned version.
# This is NOT a clean bill of health: OSV version queries return no records
# for these C/C++ packages (measured limitation, see header), and the check
# below is a targeted web search, not an exhaustive audit.
NO_ADVISORY_FOUND = [
    {"package": "soci", "pinned_version": "4.0.3",
     "note": "No CVE/GHSA surfaced for soci 4.0.3 in OSV Conan query or targeted search."},
    {"package": "nudb", "pinned_version": "2.0.9",
     "note": "No CVE/GHSA surfaced for nudb 2.0.9 in OSV Conan query or targeted search."},
    {"package": "date", "pinned_version": "3.0.4",
     "note": "No CVE/GHSA surfaced for Howard Hinnant date 3.0.4 in OSV Conan query or targeted search."},
    {"package": "xxhash", "pinned_version": "0.8.3",
     "note": "No CVE surfaced for xxHash 0.8.3. Upstream CHANGELOG: 0.8.3 fixes a "
             "correctness bug (XXH3_128bits_withSecretandSeed could produce an invalid "
             "result, #894) - not a security advisory. Source: "
             "https://raw.githubusercontent.com/Cyan4973/xxHash/dev/CHANGELOG"},
    {"package": "bzip2", "pinned_version": "1.0.8",
     "note": "No CVE surfaced for bzip2 1.0.8. Note: conanfile.py sets "
             "libarchive/*:with_bzip2 False, so bzip2 code is not compiled into the "
             "libarchive build (the package remains in the Conan graph)."},
    {"package": "doctest", "pinned_version": "2.4.11",
     "note": "Test-only dependency (not linked into xrpld). No CVE surfaced."},
    {"package": "jemalloc", "pinned_version": "5.3.0",
     "note": "Optional dependency, default OFF in conanfile.py (not linked by default). No CVE surfaced."},
    {"package": "rocksdb", "pinned_version": "10.0.1",
     "note": "No RocksDB-library CVE surfaced in targeted search (results were "
             "kernel/Kvrocks noise). FreeBSD ports reports 'none known' for rocksdb."},
    {"package": "libbacktrace", "pinned_version": "cci.20210118",
     "note": "Transitive (via grpc). No CVE surfaced."},
    {"package": "secp256k1", "pinned_version": "0.6.0",
     "note": "No public advisory found for bitcoin-core/secp256k1 C library 0.6.0 "
             "in this triage. Newer upstream releases exist (0.7.0, 0.7.1, 0.8.0 per "
             "git ls-remote tags, 2026-11-26); upgrade is available but not security-driven."},
    {"package": "ed25519-donna", "pinned_version": "unversioned snapshot",
     "note": "No version to match. Vendored ed25519.c is byte-identical to upstream "
             "master HEAD (SHA-256 491efa60...). No advisory check possible by version."},
    {"package": "antithesis-sdk-cpp", "pinned_version": "0.4.4",
     "note": "No CVE surfaced for antithesis-sdk-cpp 0.4.4."},
    {"package": "cmake", "pinned_version": "3.25.1 (Dockerfile tool)",
     "note": "Build tool, not a linked library. No CVE triaged for the tool version."},
]

NOT_QUERYABLE = [
    {"package": "ed25519-donna",
     "reason": "Unversioned vendored snapshot - no version exists to match against advisories. "
               "ed25519.c is byte-identical to upstream master HEAD (SHA-256 491efa60...). "
               "No version-scoped CVE query is possible; manual review of upstream commits is the only route."},
    {"package": "ubuntu",
     "reason": "Base image (ubuntu:24.04) - OS-level patch state is a deployment concern, not a pinned library version; out of scope for this library triage."},
    {"package": "gcc",
     "reason": "Toolchain compiler version is a build environment property, not a library with OSV advisories."},
    {"package": "python",
     "reason": "Build-script interpreter minimum (3.11); not a linked dependency."},
]

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
             "High-equivalent (no CVSS; support-status finding)": 1, "None": 4}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--raw-out", required=True)
    ap.add_argument("--findings-json", required=True)
    ap.add_argument("--findings-md", required=True)
    ap.add_argument("--records-dir", required=True)
    ap.add_argument("--controls-out", required=True)
    args = ap.parse_args()

    with open(args.deps) as f:
        deps = json.load(f)
    with open(args.graph) as f:
        graph = json.load(f)

    # ---- PASS 1: OSV version queries (curl) -------------------------------
    print("[pass1] OSV version queries via curl (ecosystem Conan)")
    raw = {"pinned_commit": PIN, "query_date_utc": QUERY_DATE, "queries": []}
    seen = set()
    queries = []
    for rec in deps.get("dependencies", []) + graph.get("dependencies", []):
        name, ver = rec.get("name"), rec.get("version")
        if not name or not ver or (name, ver) in seen:
            continue
        seen.add((name, ver))
        queries.append((name, ver))
    for name, ver in sorted(queries):
        payload = {"package": {"name": name, "ecosystem": "Conan"}, "version": ver}
        resp, err = curl_json(OSV_QUERY, payload)
        n = len(resp.get("vulns", [])) if resp else 0
        print("  conan %-14s %-12s -> %s vulns%s" %
              (name, ver, n, (" [transport error: %s]" % err) if err else ""))
        raw["queries"].append({"package": name, "version": ver,
                               "payload": payload, "response": resp,
                               "transport_error": err})
    with open(args.raw_out, "w") as f:
        json.dump(raw, f, indent=2, sort_keys=True)
    print("[pass1] saved %s (%d queries)" % (args.raw_out, len(raw["queries"])))

    # ---- PASS 1 controls: purl queries for KNOWN-vulnerable versions -------
    print("[pass1-controls] OSV purl queries (must return vulns if the method worked)")
    controls = {"pinned_commit": PIN, "query_date_utc": QUERY_DATE, "controls": []}
    for purl, expect in [
            ("pkg:github/c-ares/c-ares@1.26.0", "CVE-2024-25629"),
            ("pkg:github/sqlite/sqlite@3.48.0", "CVE-2025-3277")]:
        resp, err = curl_json(OSV_QUERY, {"package": {"purl": purl}})
        ids = [v.get("id") for v in resp.get("vulns", [])] if resp else []
        ok = expect in ids
        print("  %-38s -> %d vulns, expected %s present: %s%s" %
              (purl, len(ids), expect, ok, (" [transport error: %s]" % err) if err else ""))
        controls["controls"].append({"purl": purl, "expected_vuln": expect,
                                     "returned_ids": ids, "method_works": ok,
                                     "response": resp, "transport_error": err})
    with open(args.controls_out, "w") as f:
        json.dump(controls, f, indent=2, sort_keys=True)
    print("[pass1-controls] saved %s" % args.controls_out)

    # ---- PASS 2: fetch OSV records, recompute CVSS ------------------------
    os.makedirs(args.records_dir, exist_ok=True)
    print("[pass2] fetching OSV records by ID + recomputing CVSS 3.1")
    for finding in FINDINGS:
        fetched = {}
        for oid in finding["osv_ids"]:
            path = os.path.join(args.records_dir, oid.replace("/", "_") + ".json")
            resp, err = curl_json("%s/%s" % (OSV_VULN, oid))
            if resp:
                with open(path, "w") as f:
                    json.dump(resp, f, indent=2, sort_keys=True)
                fetched[oid] = {"status": "fetched", "file": path}
                # Prefer the vector from the fetched record when present.
                for sev in resp.get("severity", []):
                    if sev.get("type") == "CVSS_V3" and sev.get("score", "").startswith("CVSS:3.1/"):
                        if not finding.get("cvss31_vector"):
                            finding["cvss31_vector"] = sev["score"]
                        break
                # Collect reference URLs from the record as extra evidence.
                extra = [r.get("url") for r in resp.get("references", [])
                         if r.get("url") and r.get("url") not in
                         [e["url"] for e in finding["evidence"]]]
                for url in extra[:4]:
                    finding["evidence"].append({"label": "OSV record reference", "url": url})
            else:
                fetched[oid] = {"status": "fetch_failed", "error": err}
                print("  !! OSV fetch failed for %s: %s" % (oid, err))
        finding["osv_fetch"] = fetched
        vec = finding.get("cvss31_vector")
        if vec:
            score, sev = cvss31_base(vec)
            finding["cvss31_computed"] = score
            finding["cvss31_computed_severity"] = sev
            pub = finding.get("cvss31_score")
            match = (pub is not None and abs(score - pub) < 0.05
                     and sev == finding.get("cvss31_severity"))
            finding["cvss31_recomputed_matches_published"] = match
            print("  %-18s %-9s published %.1f %-8s | recomputed %.1f %-8s | match=%s" %
                  (finding["id"], finding["package"],
                   pub if pub is not None else -1, finding.get("cvss31_severity"),
                   score, sev, match))
        else:
            finding["cvss31_computed"] = None
            finding["cvss31_recomputed_matches_published"] = None
            pub_txt = ("%.1f" % finding["cvss31_score"]) if finding.get("cvss31_score") is not None else "n/a"
            print("  %-18s %-9s published %s %-8s | no vector in record; score as published" %
                  (finding["id"], finding["package"], pub_txt,
                   finding.get("cvss31_severity")))

    affected = [f for f in FINDINGS if f["status"] in ("affected", "support_status")]
    affected.sort(key=lambda f: (SEV_ORDER.get(f["cvss31_severity"], 4),
                                 -(f["cvss31_score"] or 0)))
    counts = {}
    for f in affected:
        counts[f["cvss31_severity"]] = counts.get(f["cvss31_severity"], 0) + 1

    register = {
        "pinned_commit": PIN,
        "pinned_repo": REPO,
        "generated_by": "scripts/advisory_check.py (two-pass: OSV version queries via curl + targeted OSV record fetch + curated triage)",
        "query_date_utc": QUERY_DATE,
        "method_note": "Pass 1 OSV version queries return 0 results for these C/C++ packages "
            "because their advisories are recorded as GIT commit ranges with no version/ecosystem "
            "data (proven by controls in outputs/osv-controls.json: c-ares 1.26.0 and sqlite 3.48.0 "
            "return 0 despite known CVEs). Pass 1 zeros are therefore NOT evidence of cleanliness. "
            "Pass 2 is the authoritative triage: curated CVE list with per-CVE fixed versions, "
            "applicability reasoning, OSV record fetches in outputs/osv-records/, and CVSS 3.1 "
            "scores recomputed from vectors in-script.",
        "finding_count": len(affected),
        "severity_counts": counts,
        "findings": affected,
        "not_affected": NOT_AFFECTED,
        "not_applicable": [f for f in FINDINGS if f["status"] == "not_applicable"],
        "no_advisory_found": NO_ADVISORY_FOUND,
        "not_queryable": NOT_QUERYABLE,
    }
    with open(args.findings_json, "w") as f:
        json.dump(register, f, indent=2, sort_keys=False)
    print("[register] %d affected/support findings (%s)" % (len(affected), counts))

    # ---- Markdown register -------------------------------------------------
    lines = []
    lines.append("# Advisory Findings Register - postfiatd")
    lines.append("")
    lines.append("Pinned commit: `%s` (%s)." % (PIN, REPO))
    lines.append("Method: two-pass OSV triage, queried %s, no auth. Pass 1: OSV version "
                 "queries per pinned version (raw responses in `outputs/advisory-check-raw.json`). "
                 "Pass 2: targeted OSV record fetch per CVE/GHSA plus NVD API and distro "
                 "changelogs (records in `outputs/osv-records/`). Every finding names the "
                 "pinned version tested and links its advisory." % QUERY_DATE)
    lines.append("")
    lines.append("**Pass 1 limitation (measured):** OSV version queries return 0 results for "
                 "these C/C++ packages because their advisories are recorded as GIT commit "
                 "ranges with no version/ecosystem data. Controls prove it: OSV purl queries "
                 "for c-ares 1.26.0 (known CVE-2024-25629) and sqlite 3.48.0 (known CVE-2025-3277) "
                 "both return 0. A pass-1 zero is therefore NOT evidence that a version is clean; "
                 "pass 2 is the authoritative triage.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("Total affected / support-status findings: **%d**." % len(affected))
    for sev in ("Critical", "High", "Medium", "Low"):
        if counts.get(sev):
            lines.append("- %s: %d" % (sev, counts[sev]))
    if counts.get("High-equivalent (no CVSS; support-status finding)"):
        lines.append("- Support-status (no CVSS): %d" %
                     counts["High-equivalent (no CVSS; support-status finding)"])
    lines.append("- Determined NOT affected by a checked CVE: %d" % len(NOT_AFFECTED))
    lines.append("- Not applicable (wrong product/component): %d" %
                 len([f for f in FINDINGS if f["status"] == "not_applicable"]))
    lines.append("- No advisory found in this triage (not proof of absence): %d" % len(NO_ADVISORY_FOUND))
    lines.append("")
    lines.append("## Affected findings (severity-ranked)")
    lines.append("")
    lines.append("| ID | Package @ pinned | Severity | Fixed in | Reachability |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in affected:
        score = f["cvss31_score"]
        score_txt = ("%.1f" % score) if score is not None else "n/a"
        lines.append("| %s | %s @ %s | %s (%s) | %s | %s |" %
                     (f["id"], f["package"], f["pinned_version"],
                      f["cvss31_severity"], score_txt, f["fixed_version"],
                      f["reachability"]))
    lines.append("")
    for f in affected:
        lines.append("### %s - %s @ %s" % (f["id"], f["package"], f["pinned_version"]))
        lines.append("")
        lines.append("**%s.** %s" % (f["title"], f["description"]))
        lines.append("")
        if f.get("cvss31_score") is not None:
            vec = f.get("cvss31_vector") or "(vector not recorded in fetched OSV record)"
            lines.append("- CVSS 3.1: **%.1f %s** - `%s`" %
                         (f["cvss31_score"], f["cvss31_severity"], vec))
            if f.get("cvss31_computed") is not None:
                lines.append("  - Recomputed from the vector in-script: %.1f %s (matches published: %s)" %
                             (f["cvss31_computed"], f["cvss31_computed_severity"],
                              f["cvss31_recomputed_matches_published"]))
            if f.get("cvss31_note"):
                lines.append("  - Note: %s" % f["cvss31_note"])
        else:
            lines.append("- CVSS 3.1: n/a - %s" % f["cvss31_severity"])
        if f.get("cvss40_note"):
            lines.append("- %s" % f["cvss40_note"])
        lines.append("- Fixed in: **%s**. %s" % (f["fixed_version"], f["fixed_version_source"]))
        lines.append("- Reachability: %s" % f["reachability_text"])
        lines.append("- Evidence:")
        for e in f["evidence"]:
            lines.append("  - [%s](%s)" % (e["label"], e["url"]))
        osv_fetch = f.get("osv_fetch", {})
        failed = [k for k, v in osv_fetch.items() if v.get("status") != "fetched"]
        if not osv_fetch:
            lines.append("- OSV record fetch: n/a (not a CVE; no OSV record exists)")
        elif failed:
            lines.append("- OSV record fetch: FAILED for %s (curated data retained; see NVD/distro evidence above)" % ", ".join(failed))
        else:
            lines.append("- OSV record fetch: OK (%s)" % ", ".join(sorted(osv_fetch)))
        lines.append("")
    lines.append("## Determined NOT affected")
    lines.append("")
    lines.append("| CVE | Package @ pinned | Reason |")
    lines.append("| --- | --- | --- | --- |")
    for n in NOT_AFFECTED:
        lines.append("| %s | %s @ %s | %s |" % (n["id"], n["package"], n["pinned_version"], n["reason"]))
    lines.append("")
    for n in NOT_AFFECTED:
        lines.append("- **%s** (%s @ %s): %s Evidence: %s" %
                     (n["id"], n["package"], n["pinned_version"], n["reason"], n["evidence"]))
    lines.append("")
    lines.append("## Not applicable (wrong product or component)")
    lines.append("")
    for f in FINDINGS:
        if f["status"] == "not_applicable":
            lines.append("- **%s** (%s @ %s, CVSS 3.1 %.1f %s): %s" %
                         (f["id"], f["package"], f["pinned_version"],
                          f["cvss31_score"], f["cvss31_severity"], f["reachability_text"]))
    lines.append("")
    lines.append("## No advisory found in this triage")
    lines.append("")
    lines.append("Absence of an OSV record is not proof of absence of a vulnerability - "
                 "it means no public advisory matched that exact version in OSV on the query "
                 "date, and no CVE surfaced in the targeted search. See the pass-1 limitation above.")
    lines.append("")
    for n in NO_ADVISORY_FOUND:
        lines.append("- **%s @ %s** - %s" % (n["package"], n["pinned_version"], n["note"]))
    lines.append("")
    lines.append("## Not queryable (no version to match)")
    lines.append("")
    for n in NOT_QUERYABLE:
        lines.append("- **%s** - %s" % (n["package"], n["reason"]))
    lines.append("")
    with open(args.findings_md, "w") as f:
        f.write("\n".join(lines))
    print("[register] wrote %s and %s" % (args.findings_json, args.findings_md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
