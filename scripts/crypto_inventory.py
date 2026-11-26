#!/usr/bin/env python3
"""Build the postfiatd dependency cryptographic inventory from the pinned tree.

For each cryptographic primitive / mechanism the script runs a grep over the
pinned checkout, records the hit count and representative file:line citations,
and attaches a quantum-exposure label and a verification status. Labels are
assigned from the primitive's class, not from test outcomes:

  quantum-vulnerable  - Shor's algorithm breaks the primitive outright
                        (ECDLP: Ed25519/secp256k1; integer factoring: RSA).
  quantum-reduced     - Grover's algorithm halves effective strength
                        (SHA-256 -> ~128 bit, SHA-512 -> ~256 bit,
                        RIPEMD-160 -> ~80 bit).
  not-quantum-relevant- random-number generation / entropy (no key material
                        is protected by the primitive itself).
  unverified          - the claim could not be confirmed from the tree
                        (e.g. TLS 1.3 availability, which no code sets).

A pattern with zero hits is recorded as "not-found-in-tree" with hit_count 0,
never silently dropped. Nothing here executes postfiatd or builds it.

Usage: crypto_inventory.py --tree <pinned-checkout> --deps <dependencies.json>
                            --out-json <path> --out-md <path>
"""
import argparse, json, os, re, subprocess

PIN = "0085a1ff885d6a446369cf73a4430f75af22be55"

# (id, title, primitive, patterns, quantum_label, notes, provides)
ENTRIES = [
    ("CRYPTO-01", "Ed25519 transaction / validator signatures (ed25519-donna)",
     "Ed25519 (EdDSA over Curve25519)",
     [r"ed25519_sign\(", r"ed25519_sign_open\(", r"ed25519_publickey\("],
     "quantum-vulnerable",
     "Signing and verification live in src/libxrpl/protocol/SecretKey.cpp and "
     "PublicKey.cpp. Ed25519 verify hashes nothing first (raw message to "
     "ed25519_sign_open); secp256k1 verify pre-hashes with SHA-512-Half. "
     "Keys are prefixed with a 0xED byte to distinguish them from secp256k1 keys "
     "(PublicKey.cpp). No ML-DSA/SLH-DSA alternative exists in the tree.",
     "ed25519-donna (vendored, unversioned)"),
    ("CRYPTO-02", "secp256k1 ECDSA transaction / validator signatures",
     "ECDSA over secp256k1",
     [r"secp256k1_ecdsa_sign\(", r"secp256k1_ecdsa_verify\(",
      r"secp256k1_ec_pubkey_create\(", r"secp256k1_ecdsa_signature_normalize\("],
     "quantum-vulnerable",
     "Context is created once with VERIFY|SIGN flags "
     "(include/xrpl/protocol/detail/secp256k1.h:35-36). "
     "secp256k1_context_randomize is never called from src/ or include/ "
     "(only documented in the vendored header) — context is not randomized. "
     "Signatures are normalized to low-S and required fully canonical on verify "
     "(PublicKey.cpp). No ML-DSA/SLH-DSA alternative exists in the tree.",
     "secp256k1 0.6.0 (vendored)"),
    ("CRYPTO-03", "SHA-512 and SHA-512-Half ledger / transaction hashing",
     "SHA-512 (FIPS 180-4), SHA-512-Half = first 256 bits of SHA-512",
     [r"openssl_sha512_hasher", r"sha512Half", r"SHA512\("],
     "quantum-reduced",
     "SHA-512-Half is the ledger's core hash (digest.h: basic_sha512_half_hasher): "
     "transaction signing digests, ledger entry indexes, feature IDs. "
     "Implemented via OpenSSL low-level SHA512_Init/Update/Final (digest.cpp:58-78), "
     "deprecated in OpenSSL 3.x but present in the pinned OpenSSL 1.1.1w.",
     "openssl 1.1.1w"),
    ("CRYPTO-04", "SHA-256 hashing",
     "SHA-256 (FIPS 180-4)",
     [r"openssl_sha256_hasher", r"sha256_hasher"],
     "quantum-reduced",
     "Used inside hash160 (RIPEMD160(SHA-256)) for account IDs and for the "
     "self-signed default TLS certificate (X509_sign with EVP_sha256, "
     "make_SSLContext.cpp:233). Implemented via OpenSSL low-level SHA256_* "
     "(digest.cpp:84+).",
     "openssl 1.1.1w"),
    ("CRYPTO-05", "RIPEMD-160 in account-ID derivation (hash160)",
     "RIPEMD-160",
     [r"openssl_ripemd160_hasher", r"ripemd160_hasher"],
     "quantum-reduced",
     "hash160 = RIPEMD-160(SHA-256(pubkey)) (include/xrpl/protocol/digest.h:155-157). "
     "160-bit output gives ~80-bit Grover-era strength. The tree's own comment "
     "(AccountID.cpp:145-156) debates this choice. Implemented via OpenSSL "
     "low-level RIPEMD160_* (digest.cpp:29-52), removed in OpenSSL 3.x default "
     "provider — a hard blocker for any OpenSSL 3 migration.",
     "openssl 1.1.1w"),
    ("CRYPTO-06", "TLS for peer / RPC / WebSocket ports (OpenSSL via Boost.Asio)",
     "TLS (OpenSSL 1.1.1w, cipher list TLSv1.2 only)",
     [r"defaultCipherList", r"SSL_CTX_set_cipher_list", r"SSL_OP_NO_RENEGOTIATION"],
     "quantum-vulnerable",
     "Default cipher list is \"TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL\" "
     "(make_SSLContext.cpp:104); renegotiation disabled (line 375). Key exchange "
     "is ECDHE via OpenSSL/Boost.Asio defaults — NO explicit curve or ECDH "
     "configuration exists in src/ or include/, so the negotiated groups are "
     "library defaults (unverified which). No TLS 1.3 or min/max protocol "
     "version setting exists in the tree (grep: zero hits), so TLS 1.3 "
     "availability is UNVERIFIED, not claimed on or off. No PQ KEM.",
     "openssl 1.1.1w, boost 1.83.0 (asio ssl)"),
    ("CRYPTO-07", "Self-signed default TLS certificate (ephemeral RSA-2048)",
     "RSA-2048 (ephemeral, generated at startup), X.509 self-signed, SHA-256",
     [r"defaultRSAKeyBits", r"RSA_generate_key_ex", r"X509_sign", r"EVP_PKEY_assign_RSA"],
     "quantum-vulnerable",
     "When no certificate/key is configured, postfiatd generates a 2048-bit RSA "
     "key at startup (make_SSLContext.cpp:66, 120) and a self-signed certificate "
     "with EVP_sha256() (line 233). RSA-2048 is Shor-vulnerable; the certificate "
     "is self-signed (no chain of trust) by design for the default case.",
     "openssl 1.1.1w"),
    ("CRYPTO-08", "Peer handshake channel binding (SHA-512 of TLS Finished)",
     "SHA-512 over TLS Finished messages (non-standard construction)",
     [r"hashLastMessage", r"SSL_get_finished", r"SSL_get_peer_finished"],
     "quantum-reduced",
     "Cookie = SHA-512(local Finished) XOR/combined with SHA-512(peer Finished) "
     "(src/xrpld/overlay/detail/Handshake.cpp:128-160), then signed with the "
     "node key. The code itself notes this is non-standard and cites "
     "openssl/openssl#5509 and ripple/rippled#2413. Binding strength inherits "
     "SHA-512's Grover reduction and the underlying TLS key exchange's "
     "Shor vulnerability.",
     "openssl 1.1.1w"),
    ("CRYPTO-09", "Cryptographically secure RNG (OpenSSL RAND_bytes)",
     "CSPRNG: OpenSSL RAND_bytes, seeded via RAND_poll + std::random_device",
     [r"RAND_bytes", r"RAND_poll", r"RAND_add"],
     "not-quantum-relevant",
     "csprng_engine (src/libxrpl/crypto/csprng.cpp:37-92): RAND_poll at startup, "
     "extra std::random_device entropy via RAND_add, RAND_bytes for output, "
     "throws on failure. Used for secret-key generation (SecretKey.cpp:301) and "
     "secp256k1 nonce material via the library. Entropy quality depends on the "
     "OS/OpenSSL DRBG, not on any post-quantum primitive.",
     "openssl 1.1.1w"),
    ("CRYPTO-10", "Deterministic key derivation from 128-bit seeds",
     "SHA-512-Half (Ed25519) / SHA-512 chain (secp256k1 root key)",
     [r"generateSecretKey", r"deriveDeterministicRootKey", r"sha512Half_s"],
     "quantum-reduced",
     "Ed25519 keys: SHA-512-Half(seed). secp256k1 keys: SHA-512-based root-key "
     "derivation with a 32-bit sequence counter (SecretKey.cpp:86-124, 309-327). "
     "A 128-bit seed gives at most 128-bit classical entropy regardless of the "
     "hash; Grover does not reduce seed entropy below the seed size, but the "
     "derived keys are still ECDLP keys (see CRYPTO-01/02). RFC 1751 word-list "
     "encoding of seeds exists (src/libxrpl/crypto/RFC1751.cpp).",
     "openssl 1.1.1w (SHA-512)"),
    ("CRYPTO-11", "Validator manifests (ephemeral signing-key rotation)",
     "Ed25519 or secp256k1 signatures over validator manifests",
     [r"signingKey", r"Manifest::", r"makeManifest"],
     "quantum-vulnerable",
     "Validator manifests carry a master key, an ephemeral signing key, and "
     "signatures over both (src/xrpld/app/misc/detail/Manifest.cpp:46-145). "
     "Revocation manifests rotate/revoke keys. Manifest trust is the "
     "validator-list trust root; a Shor break of the manifest key type would "
     "let an attacker forge validator identity. No PQ signature in manifests.",
     "ed25519-donna / secp256k1 0.6.0"),
    ("CRYPTO-12", "gRPC API transport (ETL for Clio)",
     "No encryption: grpc::InsecureServerCredentials() (plaintext)",
     [r"InsecureServerCredentials", r"AddListeningPort"],
     "not-quantum-relevant",
     "The gRPC server binds with InsecureServerCredentials() "
     "(src/xrpld/app/main/GRPCServer.cpp:572), with the comment 'Listen on the "
     "given address without any authentication mechanism.' The example config "
     "documents the port as ETL for Clio with a secure_gateway IP allowlist "
     "(cfg/postfiatd-example.cfg, [port_grpc]). No TLS option exists in the "
     "gRPC server code. Exposure is a deployment-topology decision, not a "
     "library version issue.",
     "grpc 1.50.1"),
    ("CRYPTO-13", "Post-quantum primitives in tree",
     "ML-DSA / ML-KEM / SLH-DSA / any NIST PQC algorithm",
     [r"ML-DSA", r"ML-KEM", r"SLH-DSA", r"Kyber", r"Dilithium", r"post-quantum"],
     "unverified",
     "ZERO hits for any post-quantum term in src/ and include/ (grep, 2026-11-26). "
     "Measured absence: no PQC signature, KEM, or hybrid scheme is implemented "
     "or referenced. This is a measured fact about the tree, not a claim about "
     "upstream rippled or about future work.",
     "none"),
    ("CRYPTO-14", "Symmetric encryption at rest / HMAC / AES",
     "AES / HMAC / any at-rest encryption",
     [r"HMAC\(", r"EVP_aes", r"AES_encrypt"],
     "unverified",
     "ZERO hits for HMAC/AES at-rest encryption calls in src/ (grep, 2026-11-26). "
     "The only EVP symmetric-adjacent call is EVP_sha256() for the X.509 signature "
     "(CRYPTO-07). Ledger data at rest is protected by RocksDB/NuDB file "
     "permissions and OS controls, not by application-layer encryption — "
     "stated as an observed absence, not as a vulnerability verdict.",
     "none"),
]


def grep_hits(tree, pattern):
    """Return (count, [file:line: text, ... up to 5]) for a regex over the tree."""
    count = 0
    hits = []
    for root, dirs, files in os.walk(tree):
        if ".git" in root:
            continue
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            if not (fn.endswith((".cpp", ".h", ".hpp", ".cc", ".c"))):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        if re.search(pattern, line):
                            count += 1
                            if len(hits) < 5:
                                rel = os.path.relpath(path, tree)
                                hits.append(f"{rel}:{i}: {line.strip()[:160]}")
            except OSError:
                continue
    return count, hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True)
    ap.add_argument("--deps", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    deps = json.load(open(args.deps, encoding="utf-8"))
    entries = []
    for (cid, title, primitive, patterns, qlabel, notes, provides) in ENTRIES:
        total = 0
        all_hits = []
        per_pattern = []
        for pat in patterns:
            c, h = grep_hits(args.tree, pat)
            per_pattern.append({"pattern": pat, "hits": c})
            total += c
            all_hits.extend(h)
        status = "measured" if total > 0 else "not-found-in-tree"
        if cid in ("CRYPTO-13", "CRYPTO-14"):
            status = "measured-absence" if total == 0 else "measured"
        entries.append({
            "id": cid, "title": title, "primitive": primitive,
            "provides": provides, "quantum_exposure": qlabel,
            "verification_status": status, "hit_count": total,
            "patterns": per_pattern, "evidence": all_hits[:8], "notes": notes,
        })
        print(f"{cid} {title[:60]:60s} hits={total:4d} [{qlabel}] {status}")
    out = {
        "pinned_commit": PIN, "pinned_repo": "postfiatorg/postfiatd",
        "generated_by": "scripts/crypto_inventory.py (grep over pinned tree; no build)",
        "entry_count": len(entries),
        "entries": entries,
    }
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    lines = [
        "# Dependency Cryptographic Inventory — postfiatd",
        "",
        f"Pinned commit: `{PIN}` (postfiatorg/postfiatd, main HEAD 2026-10-10).",
        "Generated by `scripts/crypto_inventory.py` (grep over the pinned tree; "
        "no build, no execution of postfiatd).",
        "",
        "Quantum labels: **quantum-vulnerable** = Shor breaks it outright; "
        "**quantum-reduced** = Grover halves effective strength; "
        "**not-quantum-relevant** = entropy source, no key material protected; "
        "**unverified** = could not be confirmed from the tree.",
        "",
    ]
    for e in entries:
        lines += [
            f"## {e['id']} — {e['title']}",
            "",
            f"- Primitive: {e['primitive']}",
            f"- Provided by: {e['provides']}",
            f"- Quantum exposure: **{e['quantum_exposure']}**",
            f"- Verification: {e['verification_status']} (grep hits: {e['hit_count']})",
            f"- Notes: {e['notes']}",
            "",
            "  Evidence:",
            "",
        ]
        for h in e["evidence"]:
            lines.append(f"  - `{h}`")
        if not e["evidence"]:
            lines.append("  - (no hits — measured absence)")
        lines.append("")
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"wrote {args.out_json}")
    print(f"wrote {args.out_md}")


if __name__ == "__main__":
    main()
