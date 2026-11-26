#!/usr/bin/env python3
"""Reduce a Conan `graph info --format=json` document to a dependency table.

Reads the raw graph JSON and emits one record per unique package reference:
name, version, recipe revision (rrev), remote it was downloaded from, and
the graph role (direct/test/tool/transitive, derived from the conanfile).
Duplicate nodes (same ref appearing under several parents) collapse to one.

Usage: conan_graph.py --graph <graph-info.json> --out <json>
"""
import argparse, json, re

PIN = "0085a1ff885d6a446369cf73a4430f75af22be55"

DIRECT = {"grpc", "libarchive", "nudb", "openssl", "soci", "zlib", "boost",
          "date", "lz4", "protobuf", "sqlite3", "rocksdb", "xxhash"}
TEST = {"doctest"}
TOOL = {"cmake", "b2"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    with open(args.graph, encoding="utf-8") as f:
        doc = json.load(f)
    nodes = doc["graph"]["nodes"]
    err = doc["graph"].get("error")
    if err:
        print(f"GRAPH ERROR: {err}")
        raise SystemExit(1)
    seen = {}
    for key in sorted(nodes, key=lambda k: int(k)):
        node = nodes[key]
        ref = node.get("ref") or ""
        m = re.match(r"([^/@#]+)/([^@#]+)(?:#([0-9a-f]+))?", ref)
        if not m:
            continue
        name, version, rrev = m.group(1), m.group(2), m.group(3)
        if name == "xrpl":
            continue
        role = ("direct" if name in DIRECT else
                "test" if name in TEST else
                "tool" if name in TOOL else "transitive")
        prev = seen.get(name)
        if prev is None:
            seen[name] = {
                "name": name, "version": version,
                "recipe_revision": rrev, "remote": node.get("remote"),
                "recipe": node.get("recipe"), "role": role,
                "graph_node_ids": [key],
            }
        else:
            if prev["version"] != version:
                print(f"WARNING: {name} resolved to two versions: "
                      f"{prev['version']} and {version}")
            prev["graph_node_ids"].append(key)
    deps = sorted(seen.values(), key=lambda d: d["name"])
    out = {
        "pinned_commit": PIN,
        "pinned_repo": "postfiatorg/postfiatd",
        "generated_by": "scripts/conan_graph.py from `conan graph info --format=json`",
        "conan_version": "2.34.0",
        "resolved_against": "conancenter only (xrplf remote https://conan.ripplex.io "
                            "unreachable from this build environment; see methodology)",
        "resolution_date_utc": "2026-11-26",
        "node_count_raw": len(nodes),
        "unique_packages": len(deps),
        "dependencies": deps,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"graph nodes: {len(nodes)}  unique packages: {len(deps)}")
    for d in deps:
        print(f"  {d['role']:10s} {d['name']:14s} {d['version']:16s} "
              f"rrev={d['recipe_revision']} remote={d['remote']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
