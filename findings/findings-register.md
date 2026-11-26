# Advisory Findings Register - postfiatd

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (postfiatorg/postfiatd).
Method: two-pass OSV triage, queried 2026-11-26, no auth. Pass 1: OSV version queries per pinned version (raw responses in `outputs/advisory-check-raw.json`). Pass 2: targeted OSV record fetch per CVE/GHSA plus NVD API and distro changelogs (records in `outputs/osv-records/`). Every finding names the pinned version tested and links its advisory.

**Pass 1 limitation (measured):** OSV version queries return 0 results for these C/C++ packages because their advisories are recorded as GIT commit ranges with no version/ecosystem data. Controls prove it: OSV purl queries for c-ares 1.26.0 (known CVE-2024-25629) and sqlite 3.48.0 (known CVE-2025-3277) both return 0. A pass-1 zero is therefore NOT evidence that a version is clean; pass 2 is the authoritative triage.

## Summary

Total affected / support-status findings: **13**.
- Critical: 1
- High: 6
- Medium: 2
- Low: 3
- Support-status (no CVSS): 1
- Determined NOT affected by a checked CVE: 35
- Not applicable (wrong product/component): 1
- No advisory found in this triage (not proof of absence): 13

## Affected findings (severity-ranked)

| ID | Package @ pinned | Severity | Fixed in | Reachability |
| --- | --- | --- | --- | --- |
| CVE-2025-0838 | abseil @ 20230802.1 | Critical (9.8) | 20230802.3 (SUSE-SU-2026:20268-1) / 20250127.0 | transitive-unverified |
| CVE-2023-44487 | grpc @ 1.50.1 | High (7.5) | 1.59.2 | network |
| CVE-2023-33953 | grpc @ 1.50.1 | High (7.5) | 1.53.2 | network |
| CVE-2026-4111 | libarchive @ 3.8.1 | High (7.5) | 3.8.6 | not_reachable |
| CVE-2026-4424 | libarchive @ 3.8.1 | High (7.5) | 3.8.7 | not_reachable |
| CVE-2026-5121 | libarchive @ 3.8.1 | High (7.5) | 3.8.7 | not_reachable |
| CVE-2026-14164 | libarchive @ 3.8.1 | High (7.5) | 3.8.8 | not_reachable |
| OPENSSL-1.1.1-EOL | openssl @ 1.1.1w | High-equivalent (no CVSS; support-status finding) (n/a) | Migrate to OpenSSL 3.x (3.5 LTS recommended) | n/a |
| CVE-2026-4426 | libarchive @ 3.8.1 | Medium (6.5) | 3.8.7 | not_reachable |
| CVE-2026-5745 | libarchive @ 3.8.1 | Medium (5.5) | 3.8.8 | latent |
| CVE-2026-15028 | libarchive @ 3.8.1 | Low (3.9) | 3.8.9 | latent |
| CVE-2026-16517 | libarchive @ 3.8.1 | Low (2.9) | 3.8.9 | not_reachable |
| CVE-2025-64031 | libarchive @ 3.8.1 | Low (2.5) | 3.8.2 | not_reachable |

### CVE-2025-0838 - abseil @ 20230802.1

**Heap buffer overflow in absl hash containers.** Sized constructors, reserve() and rehash() of absl::{flat,node}hash{set,map} did not impose an upper bound on their size argument; a very large size causes an integer overflow when computing the container backing-store size and a subsequent out-of-bounds memory write.

- CVSS 3.1: **9.8 Critical** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  - Recomputed from the vector in-script: 9.8 Critical (matches published: True)
- CNA (Google) CVSS 4.0 score is 5.9 Medium (CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/...); NVD CVSS 3.1 is 9.8 Critical. This register ranks on NVD CVSS 3.1, as for all other findings.
- Fixed in: **20230802.3 (SUSE-SU-2026:20268-1) / 20250127.0**. SUSE backported fix commit 5a0e2cb5 to the 20230802 line as 20230802.3; upstream fix commit 5a0e2cb5e3958dd90bb8569a2766622cb74d90c1 is in release 20250127.0.
- Reachability: AFFECTED VERSION. The flaw needs a caller to pass a huge size to the sized constructors / reserve() / rehash() of absl::{flat,node}hash{set,map}. Zero direct uses of absl::flat_hash* in postfiatd src/ and include/ (grep, pinned tree). abseil is used transitively by grpc; no attacker-controlled size argument was identified in grpc's internal use. Network reachability not demonstrated.
- Evidence:
  - [OSV record](https://osv.dev/vulnerability/CVE-2025-0838)
  - [NVD](https://nvd.nist.gov/vuln/detail/cve-2025-0838)
  - [Ubuntu CVE-2025-0838 (fixed 20230802.1-4.2ubuntu0.2)](https://ubuntu.com/security/CVE-2025-0838)
  - [Fix commit 5a0e2cb5](https://github.com/abseil/abseil-cpp/commit/5a0e2cb5e3958dd90bb8569a2766622cb74d90c1)
  - [OSV record reference](https://lists.debian.org/debian-lts-announce/2025/04/msg00012.html)
  - [OSV record reference](https://github.com/CVEProject/cvelistV5/tree/main/cves/2025/0xxx/CVE-2025-0838.json)
  - [OSV record reference](https://nvd.nist.gov/vuln/detail/CVE-2025-0838)
  - [OSV record reference](https://github.com/abseil/abseil-cpp)
- OSV record fetch: OK (CVE-2025-0838)

### CVE-2023-44487 - grpc @ 1.50.1

**HTTP/2 Rapid Reset (CISA KEV, exploited in the wild).** HTTP/2 Rapid Reset: a peer can send RST_STREAM frames immediately after requests, causing the server to do work that is then cancelled, enabling unauthenticated denial of service. Listed in CISA Known Exploited Vulnerabilities; exploited in the wild Aug-Oct 2023.

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
- Fixed in: **1.59.2**. SUSE-SU-2024:0573-1: fixed in grpc 1.59.2; OSV GIT range [0, fix commit 06021d91).
- Reachability: REACHABLE via the gRPC service. postfiatd's gRPC server is an HTTP/2 server (src/xrpld/app/main/GRPCServer.cpp:571-572, InsecureServerCredentials). Shipped configs bind [port_grpc] port 50051 on 127.0.0.1 (cfg/postfiatd-example.cfg:1466-1468); the bind address is operator-configurable, so exposure becomes remote if bound publicly. A remote unauthenticated attacker that can reach the endpoint can exhaust server resources with RST_STREAM floods.
- Evidence:
  - [OSV record](https://osv.dev/vulnerability/CVE-2023-44487)
  - [OSV record reference](http://www.openwall.com/lists/oss-security/2025/08/13/6)
  - [OSV record reference](https://access.redhat.com/security/cve/cve-2023-44487)
  - [OSV record reference](https://arstechnica.com/security/2023/10/how-ddosers-used-the-http-2-protocol-to-deliver-attacks-of-unprecedented-size/)
  - [OSV record reference](https://aws.amazon.com/security/security-bulletins/AWS-2023-011/)
- OSV record fetch: OK (CVE-2023-44487)

### CVE-2023-33953 - grpc @ 1.50.1

**HPACK table accounting error allows DoS via unwanted disconnects.** Errors in HPACK table accounting in gRPC C-core can lead to unwanted disconnects between clients and servers (denial of service).

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
- Fixed in: **1.53.2**. GHSA-496j-2rq6-j6cc ECOSYSTEM range starts at 0, fixed in 1.53.2 (pre-1.53 line).
- Reachability: REACHABLE via the gRPC service (same endpoint as CVE-2023-44487): errors in HPACK table accounting cause unwanted disconnects between clients and servers; a remote peer can trigger it with crafted HEADERS frames.
- Evidence:
  - [OSV record](https://osv.dev/vulnerability/CVE-2023-33953)
  - [OSV GHSA record](https://osv.dev/vulnerability/GHSA-496j-2rq6-j6cc)
  - [OSV record reference](https://cloud.google.com/support/bulletins#gcp-2023-022)
  - [OSV record reference](https://github.com/CVEProject/cvelistV5/tree/main/cves/2023/33xxx/CVE-2023-33953.json)
  - [OSV record reference](https://nvd.nist.gov/vuln/detail/CVE-2023-33953)
  - [OSV record reference](https://github.com/advisories/GHSA-496j-2rq6-j6cc)
  - [OSV record reference](https://github.com/rubysec/ruby-advisory-db/blob/master/gems/grpc/CVE-2023-33953.yml)
  - [OSV record reference](https://security.snyk.io/vuln/SNYK-RUBY-GRPC-5834442)
- OSV record fetch: OK (CVE-2023-33953, GHSA-496j-2rq6-j6cc)

### CVE-2026-4111 - libarchive @ 3.8.1

**RAR5 infinite-loop denial of service.** Logical deadlock between the RAR5 filter subsystem and the half-window output limiter leads to an infinite loop (DoS) on a crafted RAR5 archive.

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
  - Note: Vector not present in the fetched OSV record; score 7.5 as published (OpenCVE/NVD).
- Fixed in: **3.8.6**. Debian libarchive (3.8.6-1) changelog: 'Fix CVE-2026-4111'; Yocto: 'fixed since 3.8.6'; SUSE 3.8.6 changelog: 'RAR5 reader: fix infinite loop in rar5 decompression'.
- Reachability: NOT REACHABLE via postfiatd's use. The only libarchive consumer in the tree is extractTarLz4 (src/libxrpl/basics/Archive.cpp:36-116), which enables ONLY archive_read_support_format_tar + lz4 filter. The RAR5 reader is never enabled.
- Evidence:
  - [OSV record](https://osv.dev/vulnerability/CVE-2026-4111)
  - [Debian libarchive changelog (3.8.6 fixes 4111)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
  - [OSV record reference](https://access.redhat.com/security/cve/CVE-2026-4111)
  - [OSV record reference](https://bugzilla.redhat.com/show_bug.cgi?id=2446453)
  - [OSV record reference](https://github.com/libarchive/libarchive/pull/2877)
- OSV record fetch: OK (CVE-2026-4111)

### CVE-2026-4424 - libarchive @ 3.8.1

**RAR heap out-of-bounds read (LZSS window).** Heap out-of-bounds read in the RAR archive processing logic due to improperly sized LZSS windows (archive_read_support_format_rar.c).

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
- Fixed in: **3.8.7**. Debian libarchive (3.8.7-1) changelog: 'Fix CVE-2026-4424'; Yocto: 'fixed since 3.8.7'; SUSE 3.8.1 spec applies CVE-2026-4424.patch (3.8.1 affected).
- Reachability: NOT REACHABLE via postfiatd's use: RAR reader never enabled (Archive.cpp enables tar only).
- Evidence:
  - [NVD CVE-2026-4424 (CVSS 3.1 7.5, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-4424)
  - [Debian libarchive changelog (3.8.7 fixes 4424)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-4424)

### CVE-2026-5121 - libarchive @ 3.8.1

**zisofs block-pointer integer overflow (32-bit only).** On 32-bit systems, an integer overflow in the zisofs block pointer allocation allows a heap overflow via a crafted ISO image.

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
- Fixed in: **3.8.7**. Debian libarchive (3.8.7-1) changelog: 'Fix CVE-2026-5121'; Yocto: 'fixed since 3.8.7'.
- Reachability: NOT REACHABLE via postfiatd's use on two counts: the zisofs decompression code lives in the ISO9660 format reader (archive_read_support_format_iso9660.c), which Archive.cpp never enables; and the flaw triggers only on 32-bit systems, while the Dockerfile builds on 64-bit ubuntu:24.04.
- Evidence:
  - [NVD CVE-2026-5121 (CVSS 3.1 7.5, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5121)
  - [Debian libarchive changelog (3.8.7 fixes 5121)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-5121)

### CVE-2026-14164 - libarchive @ 3.8.1

**RAR5 reader double free.** Double free in libarchive's RAR5 reader during parsing of a specially crafted RAR5 archive (dangling pointers in init_unpack).

- CVSS 3.1: **7.5 High** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 7.5 High (matches published: True)
- Fixed in: **3.8.8**. Debian libarchive (3.8.8-1) changelog: 'Fix CVE-2026-14164'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to archive_read_support_format_rar5.c.
- Reachability: NOT REACHABLE via postfiatd's use: RAR5 reader never enabled (Archive.cpp enables tar only).
- Evidence:
  - [NVD CVE-2026-14164 (CVSS 3.1 7.5, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-14164)
  - [Debian libarchive changelog (3.8.8 fixes 14164)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-14164)

### OPENSSL-1.1.1-EOL - openssl @ 1.1.1w

**OpenSSL 1.1.1 end-of-life: no public security fixes since 2023-09-11.** OpenSSL 1.1.1 reached end of life on 2023-09-11. The pinned version 1.1.1w is the last 1.1.1 release and receives no further public security fixes.

- CVSS 3.1: n/a - High-equivalent (no CVSS; support-status finding)
- Fixed in: **Migrate to OpenSSL 3.x (3.5 LTS recommended)**. OpenSSL project: 1.1.1 EOL 2023-09-11; 1.1.1w (2023-09-11) was the final 1.1.1 release.
- Reachability: Support-status finding, not a single CVE. 1.1.1w is the final 1.1.1 release; any vulnerability discovered in the 1.1.1 line after 2023-09-11 receives no public fix. The pinned tree also blocks migration: src/libxrpl/crypto/digest.cpp uses RIPEMD160 low-level APIs removed from the OpenSSL 3.x default provider, so an upgrade needs code changes, not just a version bump (see decision memo).
- Evidence:
  - [OpenSSL 1.1.1 EOL reminder (2023-06-15)](https://www.openssl.org/blog/blog/2023/06/15/1.1.1-EOL/)
- OSV record fetch: n/a (not a CVE; no OSV record exists)

### CVE-2026-4426 - libarchive @ 3.8.1

**zisofs decompression undefined behaviour.** Undefined behaviour due to an unvalidated operand in a shift expression of the zisofs decompression code.

- CVSS 3.1: **6.5 Medium** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 6.5 Medium (matches published: True)
- Fixed in: **3.8.7**. Debian libarchive (3.8.7-1) changelog: 'Fix CVE-2026-4426'; Yocto: 'fixed since 3.8.7'; SUSE 3.8.1 spec applies CVE-2026-4426.patch.
- Reachability: NOT REACHABLE via postfiatd's use: zisofs code lives in the ISO9660 format reader, never enabled by Archive.cpp.
- Evidence:
  - [NVD CVE-2026-4426 (CVSS 3.1 6.5, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-4426)
  - [Debian libarchive changelog (3.8.7 fixes 4426)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-4426)

### CVE-2026-5745 - libarchive @ 3.8.1

**NULL pointer dereference in ACL text parsing.** NULL pointer dereference in the ACL parsing logic (archive_acl_from_text_nl) when processing a malformed ACL string in a tar archive.

- CVSS 3.1: **5.5 Medium** - `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
  - Recomputed from the vector in-script: 5.5 Medium (matches published: True)
- Fixed in: **3.8.8**. Debian libarchive (3.8.8-1) changelog: 'Fix CVE-2026-5745'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to archive_acl.c (archive_acl_from_text_nl).
- Reachability: LATENT tar-path flaw. The vulnerable function archive_acl_from_text_nl() parses ACL text from tar PAX extended headers, and Archive.cpp enables tar reading with ARCHIVE_EXTRACT_ACL (Archive.cpp:75-77). BUT extractTarLz4 is the only function in Archive.cpp and has NO caller in src/ or include/ in the pinned tree (grep, 2026-11-26), so the code path is present in libxrpl source with no in-tree execution path in xrpld as pinned. Reachable only if the utility is invoked by downstream tooling or future code.
- Evidence:
  - [NVD CVE-2026-5745 (CVSS 3.1 5.5, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5745)
  - [Debian libarchive changelog (3.8.8 fixes 5745)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-5745)

### CVE-2026-15028 - libarchive @ 3.8.1

**Heap overflow parsing tar PAX SUN.holesdata sparse attribute.** A remote attacker can trigger a heap overflow by providing a specially crafted tar archive; the issue occurs during parsing of a PAX extended header containing a malformed SUN.holesdata sparse-file attribute (CWE-805/CWE-122).

- CVSS 3.1: **3.9 Low** - `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:L`
  - Recomputed from the vector in-script: 3.9 Low (matches published: True)
- Fixed in: **3.8.9**. Debian libarchive (3.8.9-1) changelog: 'Fix CVE-2026-15028'; Ubuntu 3.8.5-1ubuntu2.2 backports the fix to archive_read_support_format_tar.c (1-byte OOB read).
- Reachability: LATENT tar-path flaw. The vulnerable code is the tar reader's PAX extended-header parsing, which Archive.cpp enables (format tar). BUT extractTarLz4 has NO caller in src/ or include/ in the pinned tree, so the code path is present in libxrpl source with no in-tree execution path in xrpld as pinned. Reachable only if the utility is invoked; the input would then be an operator-supplied local tar file (CVSS AV:L/UI:R matches: local access + user interaction).
- Evidence:
  - [NVD CVE-2026-15028 (CVSS 3.1 3.9, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-15028)
  - [Debian libarchive changelog (3.8.9 fixes 15028)](https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog)
- OSV record fetch: OK (CVE-2026-15028)

### CVE-2026-16517 - libarchive @ 3.8.1

**Signed integer overflow in ZIP writer (encrypted entries).** Signed integer overflow in archive_write_zip_header when ZIP encryption is enabled and the entry filename is crafted.

- CVSS 3.1: **2.9 Low** - `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
  - Recomputed from the vector in-script: 2.9 Low (matches published: True)
- Fixed in: **3.8.9**. Debian libarchive (3.8.9-1) changelog: 'Fix CVE-2026-16517'; Ubuntu 3.8.5-1ubuntu2.3: integer overflow in ZIP writer.
- Reachability: NOT REACHABLE via postfiatd's use: the flaw is in the ZIP writer (archive_write_set_format_zip.c) with ZIP encryption enabled. Archive.cpp uses archive_write_disk only; it never writes zip.
- Evidence:
  - [NVD CVE-2026-16517 (CVSS 3.1 2.9, vector as recorded)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-16517)
  - [Ubuntu libarchive changelog (3.8.5-1ubuntu2.3, CVE-2026-16517)](https://changelogs.ubuntu.com/changelogs/pool/main/liba/libarchive/libarchive_3.8.5-1ubuntu2.3/changelog)
- OSV record fetch: OK (CVE-2026-16517)

### CVE-2025-64031 - libarchive @ 3.8.1

**strcpy heap overflow in gzip writer.** strcpy heap overflow in the gzip writer of libarchive 3.8.x.

- CVSS 3.1: **2.5 Low** - `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`
  - Recomputed from the vector in-script: 2.5 Low (matches published: True)
  - Note: Vector not present in the fetched OSV record; score 2.5 as published by GHSA-92wx-p669-8gr9.
- Fixed in: **3.8.2**. GHSA-92wx-p669-8gr9: 'libarchive 3.8.x before 3.8.2'; SUSE 3.8.2 changelog lists the gzip-writer fix.
- Reachability: NOT REACHABLE via postfiatd's use: the flaw is in the gzip writer. Archive.cpp writes with archive_write_disk only and enables only the lz4 read filter; it never writes gzip.
- Evidence:
  - [OSV record](https://osv.dev/vulnerability/CVE-2025-64031)
  - [OSV GHSA record](https://osv.dev/vulnerability/GHSA-92wx-p669-8gr9)
  - [OSV record reference](https://gist.github.com/ttuurrnn/1365a4a9b1c3d5826a3a9bbe111f26b8)
  - [OSV record reference](https://github.com/libarchive/libarchive/blob/master/libarchive/archive_write_add_filter_gzip.c)
  - [OSV record reference](https://github.com/libarchive/libarchive/pull/2734/commits)
  - [OSV record reference](https://github.com/libarchive/libarchive/pull/2734/files)
- OSV record fetch: OK (CVE-2025-64031, GHSA-92wx-p669-8gr9)

## Determined NOT affected

| CVE | Package @ pinned | Reason |
| --- | --- | --- | --- |
| CVE-2023-1428 | grpc @ 1.50.1 | Introduced in 1.51.0 (hpack table fix), fixed in 1.53.0. 1.50.1 predates the vulnerable code. |
| CVE-2023-32731 | grpc @ 1.50.1 | Introduced BY the CVE-2023-1428 fix commit 358bfb58 (in 1.53.0), fixed in 1.56.0. 1.50.1 predates both. |
| CVE-2023-32732 | grpc @ 1.50.1 | Same introduction as CVE-2023-32731 (the 1428 fix), fixed in 1.53.1/1.54.2. 1.50.1 predates it. |
| CVE-2023-4785 | grpc @ 1.50.1 | GHSA-p25m-jpj4-qcrr ECOSYSTEM ranges start at 1.53.0. The NVD text 'starting version 1.23' is an imprecise CPE approximation; the GHSA range is authoritative. |
| CVE-2024-11407 | grpc @ 1.50.1 | Transmit-zero-copy code introduced in v1.51.0-pre1; 1.50.1 predates it. Fixed in v1.68.0-pre1 (commit e9046b2b). Also requires GRPC_ARG_TCP_TX_ZEROCOPY_ENABLED, which postfiatd does not set. |
| CVE-2025-5914 | libarchive @ 3.8.1 | Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. |
| CVE-2025-5915 | libarchive @ 3.8.1 | Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. |
| CVE-2025-5916 | libarchive @ 3.8.1 | Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. |
| CVE-2025-5917 | libarchive @ 3.8.1 | Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. |
| CVE-2025-5918 | libarchive @ 3.8.1 | Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. |
| CVE-2025-25724 | libarchive @ 3.8.1 | NVD CPE range ends at 3.7.7 inclusive ('through 3.7.7'). 3.8.1 is outside the affected range. |
| CVE-2025-60753 | libarchive @ 3.8.1 | bsdtar-tool-only flaw, fixed in 3.8.1; the bsdtar CLI tool is not linked into postfiatd. |
| CVE-2025-3277 | sqlite3 @ 3.49.1 | Affects versions < 3.49.1; 3.49.1 IS the fix version. |
| CVE-2025-29087 | sqlite3 @ 3.49.1 | Fixed in 3.49.1. |
| CVE-2025-29088 | sqlite3 @ 3.49.1 | Fixed in 3.49.1. |
| CVE-2025-7458 | sqlite3 @ 3.49.1 | Affects 3.39.2-3.41.1 only. 3.49.1 is outside the range. |
| CVE-2024-7254 | protobuf @ 3.21.12 | Protobuf Java Lite only; the pinned dependency is protobuf-cpp (C++). Not the affected product. |
| CVE-2022-1941 | protobuf @ 3.21.12 | protobuf-cpp affected through 3.21.5; 3.21.12 is newer than the fix. |
| CVE-2024-25629 | c-ares @ 1.34.9 | Fixed in 1.27.0; 1.34.9 is newer than the fix. |
| CVE-2023-31147 | c-ares @ 1.34.9 | Fixed in 1.19.1; 1.34.9 is newer than the fix. |
| CVE-2023-31130 | c-ares @ 1.34.9 | Fixed in 1.19.1; 1.34.9 is newer than the fix. |
| CVE-2023-32067 | c-ares @ 1.34.9 | Fixed in 1.19.1; 1.34.9 is newer than the fix. |
| CVE-2025-31498 | c-ares @ 1.34.9 | Affects 1.32.3-1.34.4, fixed in 1.34.5; 1.34.9 is newer than the fix. |
| CVE-2023-6129 | openssl @ 1.1.1w | Introduced in OpenSSL 3.2 (PowerPC code). The 1.1.1 line never contained the vulnerable code. |
| CVE-2024-5535 | openssl @ 1.1.1w | Affects OpenSSL 3.0-3.3 only. The 1.1.1 line is outside the range. |
| CVE-2023-6992 | zlib @ 1.3.1 | This CVE is for the Cloudflare zlib fork, not zlib.net. The pinned dependency is zlib.net 1.3.1. |
| CVE-2025-66566 | lz4 @ 1.10.0 | lz4-JAVA (yawkat) only; JNI-based implementations not affected. The pinned dependency is the C library lz4 1.10.0. |
| CVE-2024-36114 | snappy @ 1.2.1 | aircompressor (Java) only. The pinned dependency is the C++ snappy library 1.2.1. |
| CVE-2024-36124 | snappy @ 1.2.1 | iq80 Snappy (Java) only. The pinned dependency is the C++ snappy library 1.2.1. |
| CVE-2026-71498 | re2 @ 20230301 | node-re2 (npm wrapper) only; out-of-bounds read with malformed UTF-8 in the Node.js binding. The pinned dependency is the C++ re2 library. |
| CVE-2026-71430 | re2 @ 20230301 | node-re2 (npm wrapper) only. Not the C++ re2 library. |
| CVE-2026-68499 | re2 @ 20230301 | node-re2 (npm wrapper) only. Not the C++ re2 library. |
| CVE-2026-67550 | re2 @ 20230301 | node-re2 (npm wrapper) only. Not the C++ re2 library. |
| CVE-2026-107853 | secp256k1 @ 0.6.0 | tiny-secp256k1 (JavaScript wrapper) only. Not bitcoin-core/secp256k1 (C library). |
| CVE-2026-63410 | secp256k1 @ 0.6.0 | secp256k1-native (Ruby wrapper) only. Not bitcoin-core/secp256k1 (C library). |

- **CVE-2023-1428** (grpc @ 1.50.1): Introduced in 1.51.0 (hpack table fix), fixed in 1.53.0. 1.50.1 predates the vulnerable code. Evidence: GHSA-2c4m-59x9-fr3g ECOSYSTEM range [1.51.0, 1.53.0).
- **CVE-2023-32731** (grpc @ 1.50.1): Introduced BY the CVE-2023-1428 fix commit 358bfb58 (in 1.53.0), fixed in 1.56.0. 1.50.1 predates both. Evidence: GHSA-7v5x-rpf4-c6xj.
- **CVE-2023-32732** (grpc @ 1.50.1): Same introduction as CVE-2023-32731 (the 1428 fix), fixed in 1.53.1/1.54.2. 1.50.1 predates it. Evidence: GHSA-x3r6-5j9r-r2gq.
- **CVE-2023-4785** (grpc @ 1.50.1): GHSA-p25m-jpj4-qcrr ECOSYSTEM ranges start at 1.53.0. The NVD text 'starting version 1.23' is an imprecise CPE approximation; the GHSA range is authoritative. Evidence: OSV record GHSA-p25m-jpj4-qcrr.
- **CVE-2024-11407** (grpc @ 1.50.1): Transmit-zero-copy code introduced in v1.51.0-pre1; 1.50.1 predates it. Fixed in v1.68.0-pre1 (commit e9046b2b). Also requires GRPC_ARG_TCP_TX_ZEROCOPY_ENABLED, which postfiatd does not set. Evidence: Wiz CVE-2024-11407 analysis: https://www.wiz.io/vulnerability-database/cve/cve-2024-11407 ; Debian grpc tracker: https://tracker.debian.org/pkg/grpc
- **CVE-2025-5914** (libarchive @ 3.8.1): Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. Evidence: Upstream release notes / GHSA.
- **CVE-2025-5915** (libarchive @ 3.8.1): Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. Evidence: Upstream release notes / GHSA.
- **CVE-2025-5916** (libarchive @ 3.8.1): Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. Evidence: Upstream release notes / GHSA.
- **CVE-2025-5917** (libarchive @ 3.8.1): Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. Evidence: Upstream release notes / GHSA.
- **CVE-2025-5918** (libarchive @ 3.8.1): Introduced in 3.8.0, fixed in 3.8.1. 3.8.1 IS the fix version. Evidence: Upstream release notes / GHSA.
- **CVE-2025-25724** (libarchive @ 3.8.1): NVD CPE range ends at 3.7.7 inclusive ('through 3.7.7'). 3.8.1 is outside the affected range. Evidence: NVD API record: cpe libarchive, versionEndIncluding 3.7.7.
- **CVE-2025-60753** (libarchive @ 3.8.1): bsdtar-tool-only flaw, fixed in 3.8.1; the bsdtar CLI tool is not linked into postfiatd. Evidence: Upstream advisory.
- **CVE-2025-3277** (sqlite3 @ 3.49.1): Affects versions < 3.49.1; 3.49.1 IS the fix version. Evidence: SQLite forum / upstream changelog.
- **CVE-2025-29087** (sqlite3 @ 3.49.1): Fixed in 3.49.1. Evidence: Upstream changelog.
- **CVE-2025-29088** (sqlite3 @ 3.49.1): Fixed in 3.49.1. Evidence: Upstream changelog.
- **CVE-2025-7458** (sqlite3 @ 3.49.1): Affects 3.39.2-3.41.1 only. 3.49.1 is outside the range. Evidence: Upstream advisory.
- **CVE-2024-7254** (protobuf @ 3.21.12): Protobuf Java Lite only; the pinned dependency is protobuf-cpp (C++). Not the affected product. Evidence: GHSA record (Java Lite).
- **CVE-2022-1941** (protobuf @ 3.21.12): protobuf-cpp affected through 3.21.5; 3.21.12 is newer than the fix. Evidence: GHSA record.
- **CVE-2024-25629** (c-ares @ 1.34.9): Fixed in 1.27.0; 1.34.9 is newer than the fix. Evidence: c-ares security advisory.
- **CVE-2023-31147** (c-ares @ 1.34.9): Fixed in 1.19.1; 1.34.9 is newer than the fix. Evidence: c-ares security advisory.
- **CVE-2023-31130** (c-ares @ 1.34.9): Fixed in 1.19.1; 1.34.9 is newer than the fix. Evidence: c-ares security advisory.
- **CVE-2023-32067** (c-ares @ 1.34.9): Fixed in 1.19.1; 1.34.9 is newer than the fix. Evidence: c-ares security advisory.
- **CVE-2025-31498** (c-ares @ 1.34.9): Affects 1.32.3-1.34.4, fixed in 1.34.5; 1.34.9 is newer than the fix. Evidence: IBM security bulletin.
- **CVE-2023-6129** (openssl @ 1.1.1w): Introduced in OpenSSL 3.2 (PowerPC code). The 1.1.1 line never contained the vulnerable code. Evidence: OpenSSL security advisory.
- **CVE-2024-5535** (openssl @ 1.1.1w): Affects OpenSSL 3.0-3.3 only. The 1.1.1 line is outside the range. Evidence: OpenSSL security advisory.
- **CVE-2023-6992** (zlib @ 1.3.1): This CVE is for the Cloudflare zlib fork, not zlib.net. The pinned dependency is zlib.net 1.3.1. Evidence: NVD record (Cloudflare zlib product).
- **CVE-2025-66566** (lz4 @ 1.10.0): lz4-JAVA (yawkat) only; JNI-based implementations not affected. The pinned dependency is the C library lz4 1.10.0. Evidence: Ubuntu CVE-2025-66566: https://ubuntu.com/security/CVE-2025-66566
- **CVE-2024-36114** (snappy @ 1.2.1): aircompressor (Java) only. The pinned dependency is the C++ snappy library 1.2.1. Evidence: GHSA record (airlift aircompressor).
- **CVE-2024-36124** (snappy @ 1.2.1): iq80 Snappy (Java) only. The pinned dependency is the C++ snappy library 1.2.1. Evidence: GHSA record (iq80 snappy).
- **CVE-2026-71498** (re2 @ 20230301): node-re2 (npm wrapper) only; out-of-bounds read with malformed UTF-8 in the Node.js binding. The pinned dependency is the C++ re2 library. Evidence: OX Radar re2 (npm) advisory list.
- **CVE-2026-71430** (re2 @ 20230301): node-re2 (npm wrapper) only. Not the C++ re2 library. Evidence: OX Radar re2 (npm) advisory list.
- **CVE-2026-68499** (re2 @ 20230301): node-re2 (npm wrapper) only. Not the C++ re2 library. Evidence: OX Radar re2 (npm) advisory list.
- **CVE-2026-67550** (re2 @ 20230301): node-re2 (npm wrapper) only. Not the C++ re2 library. Evidence: OX Radar re2 (npm) advisory list.
- **CVE-2026-107853** (secp256k1 @ 0.6.0): tiny-secp256k1 (JavaScript wrapper) only. Not bitcoin-core/secp256k1 (C library). Evidence: OSV / GHSA record (npm package).
- **CVE-2026-63410** (secp256k1 @ 0.6.0): secp256k1-native (Ruby wrapper) only. Not bitcoin-core/secp256k1 (C library). Evidence: OSV / GHSA record (Ruby gem).

## Not applicable (wrong product or component)

- **CVE-2026-11460** (boost @ 1.83.0, CVSS 3.1 7.3 High): NOT APPLICABLE. The flaw is in Boost.Serialization. postfiatd links these Boost components (conanfile.py / CMakeLists): chrono, container, coroutine, date_time, filesystem, json, program_options, regex, system, thread. Zero hits for boost::serialization / boost/archive in src/ and include/ (grep, pinned tree). The vulnerable component is not linked.

## No advisory found in this triage

Absence of an OSV record is not proof of absence of a vulnerability - it means no public advisory matched that exact version in OSV on the query date, and no CVE surfaced in the targeted search. See the pass-1 limitation above.

- **soci @ 4.0.3** - No CVE/GHSA surfaced for soci 4.0.3 in OSV Conan query or targeted search.
- **nudb @ 2.0.9** - No CVE/GHSA surfaced for nudb 2.0.9 in OSV Conan query or targeted search.
- **date @ 3.0.4** - No CVE/GHSA surfaced for Howard Hinnant date 3.0.4 in OSV Conan query or targeted search.
- **xxhash @ 0.8.3** - No CVE surfaced for xxHash 0.8.3. Upstream CHANGELOG: 0.8.3 fixes a correctness bug (XXH3_128bits_withSecretandSeed could produce an invalid result, #894) - not a security advisory. Source: https://raw.githubusercontent.com/Cyan4973/xxHash/dev/CHANGELOG
- **bzip2 @ 1.0.8** - No CVE surfaced for bzip2 1.0.8. Note: conanfile.py sets libarchive/*:with_bzip2 False, so bzip2 code is not compiled into the libarchive build (the package remains in the Conan graph).
- **doctest @ 2.4.11** - Test-only dependency (not linked into xrpld). No CVE surfaced.
- **jemalloc @ 5.3.0** - Optional dependency, default OFF in conanfile.py (not linked by default). No CVE surfaced.
- **rocksdb @ 10.0.1** - No RocksDB-library CVE surfaced in targeted search (results were kernel/Kvrocks noise). FreeBSD ports reports 'none known' for rocksdb.
- **libbacktrace @ cci.20210118** - Transitive (via grpc). No CVE surfaced.
- **secp256k1 @ 0.6.0** - No public advisory found for bitcoin-core/secp256k1 C library 0.6.0 in this triage. Newer upstream releases exist (0.7.0, 0.7.1, 0.8.0 per git ls-remote tags, 2026-11-26); upgrade is available but not security-driven.
- **ed25519-donna @ unversioned snapshot** - No version to match. Vendored ed25519.c is byte-identical to upstream master HEAD (SHA-256 491efa60...). No advisory check possible by version.
- **antithesis-sdk-cpp @ 0.4.4** - No CVE surfaced for antithesis-sdk-cpp 0.4.4.
- **cmake @ 3.25.1 (Dockerfile tool)** - Build tool, not a linked library. No CVE triaged for the tool version.

## Not queryable (no version to match)

- **ed25519-donna** - Unversioned vendored snapshot - no version exists to match against advisories. ed25519.c is byte-identical to upstream master HEAD (SHA-256 491efa60...). No version-scoped CVE query is possible; manual review of upstream commits is the only route.
- **ubuntu** - Base image (ubuntu:24.04) - OS-level patch state is a deployment concern, not a pinned library version; out of scope for this library triage.
- **gcc** - Toolchain compiler version is a build environment property, not a library with OSV advisories.
- **python** - Build-script interpreter minimum (3.11); not a linked dependency.
