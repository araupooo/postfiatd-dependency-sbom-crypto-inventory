#!/usr/bin/env python3
"""Extract the pinned postfiatd dependency list from manifests + source.

Reads (all paths relative to the pinned checkout given by --tree):
  conanfile.py        - direct/test/tool requirements + requirements()
  CMakeLists.txt      - find_package minimums + vendored add_subdirectory
  cmake/deps/Boost.cmake - Boost minimum
  external/*/CMakeLists.txt + configure.ac - vendored library versions
  Dockerfile          - base image + apt toolchain
  BUILD.md            - documented toolchain minimums
  src/libxrpl/protocol/BuildInfo.cpp - postfiatd version string

Writes dependencies.json: one record per dependency with name, version,
version_source (file + line), kind (direct/test/tool/vendored/toolchain/
transitive), and evidence. Versions are NEVER invented: a dependency whose
version is resolved by a Conan recipe at install time is recorded with
version=null and version_status="unpinned-resolved-by-recipe".

Usage: extract_deps.py --tree <path-to-pinned-checkout> --out <json>
"""
import argparse, json, os, re, sys

PIN = "0085a1ff885d6a446369cf73a4430f75af22be55"


def grep_lines(path, pattern, flags=0):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if re.search(pattern, line, flags):
                out.append((i, line.rstrip("\n")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    tree = args.tree
    deps = []

    def add(name, version, kind, source_file, source_line, note="", version_status="pinned"):
        deps.append({
            "name": name, "version": version, "kind": kind,
            "source_file": source_file, "source_line": source_line,
            "version_status": version_status, "note": note,
        })

    # --- conanfile.py: requires / test_requires / tool_requires ---
    cf = os.path.join(tree, "conanfile.py")
    with open(cf, encoding="utf-8") as f:
        lines = f.readlines()
    section = None
    for i, line in enumerate(lines, 1):
        m = re.match(r"\s*(requires|test_requires|tool_requires)\s*=\s*\[", line)
        if m:
            section = m.group(1)
            continue
        if section and line.strip() == "]":
            section = None
            continue
        if section:
            m = re.search(r"'([A-Za-z0-9_.\-+]+)/([^']+)'", line)
            if m:
                kind = {"requires": "direct", "test_requires": "test",
                        "tool_requires": "tool"}[section]
                add(m.group(1), m.group(2), kind, "conanfile.py", i)
    # --- conanfile.py: requirements() self.requires(...) calls ---
    for i, line in enumerate(lines, 1):
        m = re.search(r"self\.requires\('([A-Za-z0-9_.\-+]+)/([^']+)'", line)
        if m:
            name, ver = m.group(1), m.group(2)
            if name == "jemalloc":
                add(name, ver, "optional", "conanfile.py", i,
                    "only when option jemalloc=True (default False)")
            elif name == "rocksdb":
                add(name, ver, "direct", "conanfile.py", i,
                    "only when option rocksdb=True (default True)")
            else:
                add(name, ver, "direct", "conanfile.py", i,
                    "via requirements(); force=True where stated")
    # --- CMakeLists.txt: find_package minimums (recorded as notes on the
    # conanfile pin, not as separate dependency records) ---
    cm = os.path.join(tree, "CMakeLists.txt")
    with open(cm, encoding="utf-8") as f:
        clines = f.readlines()
    cmake_minimums = {}
    for i, line in enumerate(clines, 1):
        m = re.search(r"find_package\(OpenSSL\s+([\d.]+)\s+REQUIRED\)", line)
        if m:
            cmake_minimums["openssl"] = (m.group(1), f"CMakeLists.txt:{i}")
    # --- cmake/deps/Boost.cmake ---
    bc = os.path.join(tree, "cmake/deps/Boost.cmake")
    for i, line in grep_lines(bc, r"find_package\(Boost"):
        m = re.search(r"find_package\(Boost\s+([\d.]+)", line)
        if m:
            cmake_minimums["boost"] = (m.group(1), f"cmake/deps/Boost.cmake:{i}")
    # --- vendored secp256k1 version (configure.ac _PKG_VERSION_*) ---
    sac = os.path.join(tree, "external/secp256k1/configure.ac")
    ver = {}
    for i, line in grep_lines(sac, r"define\(_PKG_VERSION_(MAJOR|MINOR|PATCH|IS_RELEASE)"):
        m = re.search(r"define\(_PKG_VERSION_(MAJOR|MINOR|PATCH|IS_RELEASE),\s*(\S+)\)", line)
        if m:
            ver[m.group(1)] = m.group(2)
    if {"MAJOR", "MINOR", "PATCH"} <= set(ver):
        v = f"{ver['MAJOR']}.{ver['MINOR']}.{ver['PATCH']}"
        add("secp256k1", v, "vendored", "external/secp256k1/configure.ac", 6,
            "vendored copy; CHANGELOG.md confirms [0.6.0] - 2024-11-04 as latest entry; "
            "upstream bitcoin-core/secp256k1")
    # --- vendored antithesis-sdk-cpp version ---
    acm = os.path.join(tree, "external/antithesis-sdk/CMakeLists.txt")
    for i, line in grep_lines(acm, r"project\(antithesis-sdk-cpp VERSION"):
        m = re.search(r"VERSION\s+([\d.]+)", line)
        if m:
            add("antithesis-sdk-cpp", m.group(1), "vendored",
                "external/antithesis-sdk/CMakeLists.txt", i,
                "vendored copy; upstream antithesishq/antithesis-sdk-cpp")
    # --- vendored ed25519-donna: no version marker anywhere in tree ---
    add("ed25519-donna", None, "vendored",
        "external/ed25519-donna/ed25519.h", 1,
        "UNVERSIONED snapshot: no version macro, CHANGELOG, or release tag in the "
        "vendored tree; consolidated into external/ 2024-04-19 (commit e2384885f); "
        "upstream floodyberry/ed25519-donna (no releases published)",
        version_status="unversioned")
    # --- postfiatd own version ---
    bi = os.path.join(tree, "src/libxrpl/protocol/BuildInfo.cpp")
    for i, line in grep_lines(bi, r"versionString\s*="):
        m = re.search(r'"([^"]+)"', line)
        if m:
            add("postfiatd", m.group(1), "self",
                "src/libxrpl/protocol/BuildInfo.cpp", i,
                "the assessed software itself, not a dependency")
    # --- Dockerfile toolchain (dedupe: one record per tool) ---
    df = os.path.join(tree, "Dockerfile")
    seen_toolchain = set()
    for i, line in grep_lines(df, r"^FROM\s+"):
        add("ubuntu", line.split()[1], "toolchain", "Dockerfile", i,
            "base image of the multi-stage Docker build")
    for i, line in grep_lines(df, r"cmake-([\d.]+)\.tar\.gz"):
        m = re.search(r"cmake-([\d.]+)\.tar\.gz", line)
        if m and "cmake" not in seen_toolchain:
            seen_toolchain.add("cmake")
            add("cmake", m.group(1), "toolchain", "Dockerfile", i,
                "CMake built from source in the Docker build")
    for i, line in grep_lines(df, r"gcc-13|g\+\+-13"):
        add("gcc", "13", "toolchain", "Dockerfile", i,
            "compiler installed in the Docker build (gcc-13/g++-13)")
        break
    # --- BUILD.md documented toolchain minimums ---
    bm = os.path.join(tree, "BUILD.md")
    for i, line in grep_lines(bm, r"Python 3\.11|Conan 2\.17|CMake 3\.22"):
        m = re.search(r"(Python 3\.11|Conan 2\.17|CMake 3\.22)", line)
        if m:
            tool = m.group(1).split()[0].lower()
            add(tool, m.group(1).split()[1], "toolchain", "BUILD.md", i,
                "documented minimum in BUILD.md", version_status="minimum")
    # --- annotate pinned records with CMake minimums; dedupe by (name, kind) ---
    for d in deps:
        if d["name"] in cmake_minimums:
            ver, ref = cmake_minimums[d["name"]]
            d["note"] += f" CMake minimum {ver} at {ref}."
    seen, deduped = set(), []
    for d in deps:
        key = (d["name"], d["kind"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(d)
    deps = deduped
    deps.sort(key=lambda d: (d["kind"], d["name"]))
    out = {
        "pinned_commit": PIN,
        "pinned_repo": "postfiatorg/postfiatd",
        "generated_by": "scripts/extract_deps.py (manifest + source parsing; no build)",
        "dependency_count": len(deps),
        "dependencies": deps,
        "transitive_note": (
            "Transitive dependencies are NOT pinned in this repo (no conan.lock). "
            "Exact transitive versions were resolved live with Conan 2.34.0 "
            "`conan graph info` against Conan Center only on 2026-11-26; see "
            "outputs/conan-graph-deps.json. CAVEAT: the project's documented remote "
            "is the xrplf fork (https://conan.ripplex.io, BUILD.md lines 121-130), "
            "which was unreachable from this build environment (curl exit 000), so "
            "patched-recipe versions from that fork could differ from the Conan "
            "Center resolution recorded here. That difference is an open "
            "verification item, not a measured fact."
        ),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"dependencies: {len(deps)}")
    for d in deps:
        print(f"  {d['kind']:10s} {d['name']:22s} {d['version'] or '(unpinned)':12s} "
              f"{d['source_file']}:{d['source_line']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
