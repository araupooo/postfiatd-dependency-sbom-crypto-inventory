#!/usr/bin/env python3
"""Generate SPDX 2.3 JSON and CycloneDX 1.5 JSON SBOMs for pinned postfiatd.

Inputs (all produced by earlier harness steps, all pinned to one commit):
  outputs/dependencies.json      - manifest + source-parsed dependencies
  outputs/conan-graph-deps.json  - Conan graph resolution (transitive versions)
  outputs/conan-graph-info-raw.json - raw graph (licenses + homepages)

Outputs:
  sbom/postfiatd-<shortsha>.spdx.json
  sbom/postfiatd-<shortsha>.cyclonedx.json

Rules:
  * A package is listed only if it is named in a pinned-tree manifest, in the
    Conan graph, or is a vendored in-tree library. Nothing is invented.
  * Unpinned / unversioned items carry versionInfo "NOASSERTION" (SPDX) or
    no version (CycloneDX) plus an explicit annotation/property stating why.
  * Licenses come from the Conan recipe metadata (graph) or the vendored
    tree's own LICENSE/COPYING file; unknown licenses are NOASSERTION.
  * The root package is postfiatd 1.0.9 at the pinned commit.

Usage: generate_sbom.py --deps <dependencies.json> --graph <conan-graph-deps.json>
                         --raw-graph <conan-graph-info-raw.json>
                         --outdir <sbom dir>
"""
import argparse, hashlib, json, os, uuid

PIN = "0085a1ff885d6a446369cf73a4430f75af22be55"
SHORT = PIN[:8]
REPO = "postfiatorg/postfiatd"
REPO_URL = "https://github.com/postfiatorg/postfiatd"

# Vendored libraries: upstream homepage + license verified in the pinned tree.
VENDORED = {
    "secp256k1": {
        "homepage": "https://github.com/bitcoin-core/secp256k1",
        "license": "MIT",  # external/secp256k1/COPYING (MIT text)
        "note": "Vendored copy in external/secp256k1, version 0.6.0 from configure.ac.",
    },
    "ed25519-donna": {
        "homepage": "https://github.com/floodyberry/ed25519-donna",
        "license": "LicenseRef-Public-Domain",  # ed25519.c: "Public domain by Andrew M."
        "note": ("Vendored unversioned snapshot in external/ed25519-donna; "
                 "ed25519.c SHA-256 matches upstream master HEAD as of 2026-11-26."),
    },
    "antithesis-sdk-cpp": {
        "homepage": "https://github.com/antithesishq/antithesis-sdk-cpp",
        "license": "MIT",  # external/antithesis-sdk/LICENSE
        "note": "Vendored copy in external/antithesis-sdk, version 0.4.4 from CMakeLists.txt.",
    },
}

# Toolchain items are build-time only, not linked libraries.
TOOLCHAIN_NOTE = "Build toolchain (not a linked library)."


def spdx_id(name):
    safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in name)
    return f"SPDXRef-Package-{safe}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--raw-graph", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    deps = json.load(open(args.deps, encoding="utf-8"))["dependencies"]
    graph = json.load(open(args.graph, encoding="utf-8"))["dependencies"]
    raw = json.load(open(args.raw_graph, encoding="utf-8"))
    meta = {}
    for node in raw["graph"]["nodes"].values():
        ref = (node.get("ref") or "").split("#")[0].split("@")[0]
        name = ref.split("/")[0] if "/" in ref else ref
        if name and name not in meta:
            lic = node.get("license")
            if isinstance(lic, list):
                lic = " AND ".join(lic)
            meta[name] = {"license": lic, "homepage": node.get("homepage")}

    # Merge: manifest records are authoritative for direct/vendored/toolchain;
    # graph records supply transitive versions + recipe revisions.
    pkgs = {}
    for d in deps:
        name = d["name"]
        if name == "postfiatd":
            continue
        pkgs[name] = {
            "name": name, "version": d["version"], "kind": d["kind"],
            "source": f"{d['source_file']}:{d['source_line']}",
            "note": d.get("note", ""), "status": d.get("version_status", "pinned"),
        }
    for g in graph:
        name = g["name"]
        if name in pkgs:
            pkgs[name]["recipe_revision"] = g.get("recipe_revision")
            pkgs[name]["remote"] = g.get("remote")
            if pkgs[name]["version"] != g["version"]:
                # Same name, different role: e.g. cmake 3.25.1 is the
                # Dockerfile-pinned build tool, while cmake 3.31.12/4.5.1 are
                # tool-requires of Conan recipes. Keep the manifest version
                # and record the graph version in the note.
                pkgs[name]["note"] += (f" Conan graph also resolves this name "
                    f"as a tool-require at version {g['version']} "
                    f"(rrev {g.get('recipe_revision')}).")
            elif pkgs[name]["kind"] in ("direct", "test", "tool"):
                pass
        else:
            pkgs[name] = {
                "name": name, "version": g["version"], "kind": g["role"],
                "source": "conan graph resolution (conancenter, 2026-11-26)",
                "note": f"Transitive dependency resolved by Conan recipe; "
                        f"rrev {g.get('recipe_revision')}.",
                "status": "resolved-by-recipe",
                "recipe_revision": g.get("recipe_revision"),
                "remote": g.get("remote"),
            }
    # cmake appears twice in the graph (3.31.12 and 4.5.1 as tool-requires of
    # different recipes); record both as tool-require versions.
    pkgs["cmake-tool-requires"] = {
        "name": "cmake (tool-requires)", "version": "3.31.12 and 4.5.1",
        "kind": "tool",
        "source": "conan graph resolution (conancenter, 2026-11-26)",
        "note": "CMake versions pulled as tool-requires by Conan recipes "
                "(grpc/protobuf toolchains); distinct from the Docker-pinned "
                "CMake 3.25.1 used to build postfiatd itself.",
        "status": "resolved-by-recipe",
    }

    packages = sorted(pkgs.values(), key=lambda p: p["name"])
    print(f"SBOM packages: {len(packages)} (+ postfiatd root)")

    # ---------------- SPDX 2.3 ----------------
    doc_ns = (f"https://github.com/{REPO}/sbom/postfiatd-{SHORT}-"
              f"{uuid.uuid5(uuid.NAMESPACE_URL, REPO_URL + PIN)}")
    spdx_pkgs = [{
        "SPDXID": "SPDXRef-Package-postfiatd",
        "name": "postfiatd",
        "versionInfo": "1.0.9",
        "supplier": "Organization: PostFiat",
        "downloadLocation": REPO_URL,
        "filesAnalyzed": False,
        "licenseConcluded": "ISC",
        "licenseDeclared": "ISC",
        "copyrightText": "NOASSERTION",
        "description": "PostFiat daemon (XRP Ledger protocol, C++), commit " + PIN,
        "externalRefs": [{
            "referenceCategory": "OTHER",
            "referenceType": "git-commit",
            "referenceLocator": PIN,
        }],
    }]
    relationships = []
    for p in packages:
        lic = None
        dl = "NOASSERTION"
        if p["name"] in VENDORED:
            lic = VENDORED[p["name"]]["license"]
            dl = VENDORED[p["name"]]["homepage"]
            desc = VENDORED[p["name"]]["note"]
        elif p["name"] in meta:
            lic = meta[p["name"]].get("license") or "NOASSERTION"
            dl = meta[p["name"]].get("homepage") or "NOASSERTION"
            desc = p["note"]
        else:
            lic = "NOASSERTION"
            desc = p["note"]
        entry = {
            "SPDXID": spdx_id(p["name"]),
            "name": p["name"],
            "versionInfo": p["version"] if p["version"] else "NOASSERTION",
            "supplier": "NOASSERTION",
            "downloadLocation": dl,
            "filesAnalyzed": False,
            "licenseConcluded": lic,
            "licenseDeclared": lic,
            "copyrightText": "NOASSERTION",
            "description": desc,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": ("pkg:conan/%s@%s" % (p["name"], p["version"]))
                if p["version"] and p["name"] not in VENDORED else "NOASSERTION",
            }],
            "annotations": [{
                "annotationDate": "2026-11-26T14:26:00Z",
                "annotationType": "OTHER",
                "annotator": "Tool: postfiatd-sbom-harness",
                "comment": (f"kind={p['kind']}; version_status={p['status']}; "
                            f"source={p['source']}"
                            + (f"; conan recipe rrev={p['recipe_revision']}"
                               if p.get("recipe_revision") else "")),
            }],
        }
        spdx_pkgs.append(entry)
        rel = "DEPENDENCY_OF" if p["kind"] in ("direct", "transitive") else \
              "BUILD_TOOL_OF" if p["kind"] in ("tool", "toolchain") else \
              "DEPENDENCY_OF"
        relationships.append({
            "spdxElementId": spdx_id(p["name"]),
            "relationshipType": rel,
            "relatedSpdxElement": "SPDXRef-Package-postfiatd",
        })
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"postfiatd-{SHORT}-sbom",
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": "2026-11-26T14:26:00Z",
            "creators": ["Tool: postfiatd-sbom-harness (scripts/generate_sbom.py)"],
        },
        "documentDescribes": ["SPDXRef-Package-postfiatd"],
        "packages": spdx_pkgs,
        "relationships": relationships,
    }
    os.makedirs(args.outdir, exist_ok=True)
    spdx_path = os.path.join(args.outdir, f"postfiatd-{SHORT}.spdx.json")
    with open(spdx_path, "w", encoding="utf-8") as f:
        json.dump(spdx, f, indent=2)
        f.write("\n")

    # ---------------- CycloneDX 1.5 ----------------
    def cdx_scope(kind):
        return {"direct": "required", "transitive": "required",
                "vendored": "required", "test": "optional",
                "tool": "optional", "toolchain": "optional",
                "optional": "optional"}.get(kind, "required")

    components = []
    for p in packages:
        lic = None
        url = None
        if p["name"] in VENDORED:
            lic = VENDORED[p["name"]]["license"]
            url = VENDORED[p["name"]]["homepage"]
        elif p["name"] in meta:
            lic = meta[p["name"]].get("license")
            url = meta[p["name"]].get("homepage")
        comp = {
            "type": "library",
            "bom-ref": f"pkg:conan/{p['name']}@{p['version']}" if p["version"] and p["name"] not in VENDORED
                       else f"vendored:{p['name']}",
            "name": p["name"],
            "scope": cdx_scope(p["kind"]),
            "description": p["note"],
            "properties": [
                {"name": "postfiatd:kind", "value": p["kind"]},
                {"name": "postfiatd:version_status", "value": p["status"]},
                {"name": "postfiatd:source", "value": p["source"]},
            ],
        }
        if p["version"]:
            comp["version"] = p["version"]
        if p.get("recipe_revision"):
            comp["properties"].append(
                {"name": "postfiatd:conan_recipe_revision",
                 "value": p["recipe_revision"]})
        if lic and lic != "LicenseRef-Public-Domain":
            comp["licenses"] = [{"license": {"id": lic}}] \
                if lic in ("MIT", "Apache-2.0", "BSL-1.0", "BSD-2-Clause",
                           "BSD-3-Clause", "Zlib", "OpenSSL", "Unlicense",
                           "bzip2-1.0.6", "ISC") else [{"license": {"name": lic}}]
        elif lic == "LicenseRef-Public-Domain":
            comp["licenses"] = [{"license": {"name": "Public Domain"}}]
        if url:
            comp["externalReferences"] = [{"type": "website", "url": url}]
        components.append(comp)
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, REPO_URL + PIN)}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-11-26T14:26:00Z",
            "tools": [{"vendor": "postfiatd-sbom-harness",
                       "name": "generate_sbom.py", "version": "1.0"}],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:github/{REPO}@{PIN}",
                "name": "postfiatd",
                "version": "1.0.9",
                "description": "PostFiat daemon (XRP Ledger protocol, C++), commit " + PIN,
                "licenses": [{"license": {"id": "ISC"}}],
                "externalReferences": [{"type": "vcs", "url": REPO_URL}],
            },
        },
        "components": components,
    }
    cdx_path = os.path.join(args.outdir, f"postfiatd-{SHORT}.cyclonedx.json")
    with open(cdx_path, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2)
        f.write("\n")
    for path in (spdx_path, cdx_path):
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        print(f"  {path}\n    sha256: {h}")
    print(f"wrote {spdx_path}")
    print(f"wrote {cdx_path}")


if __name__ == "__main__":
    main()
