#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证据行断言：把论文里引用的每一行代码变成可机检的正则。

每个系统声明一条"关键绑定（或缺失绑定）证据"，脚本在固定版本的源码里
查找它。任何人跑一遍就知道论文引用的行是否真的存在。
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (system, file, regex, what it proves)
CHECKS = [
    ("snarkjs", "_refs/systems/snarkjs.js",
     r"transcript\.addScalar\(Fr\.e\(publicSignals\[i\]\)\)",
     "public signals absorbed before the first challenge"),
    ("gnark backend", "_refs/gnark/backend/plonk/bls12-381/verify.go",
     r"bindPublicData\(fs, \"gamma\", vk, publicWitness\)",
     "key and public inputs bound to gamma"),
    ("gnark std", "_refs/systems/gnark-std-verifier.go",
     r"bindPublicData\(fs, \"gamma\", vk, witness\)",
     "in-circuit verifier mirrors the native binding"),
    ("Halo2", "_refs/systems/halo2-plonk-verifier.rs",
     r"vk\.hash_into\(transcript\)",
     "verification key hashed into the transcript"),
    ("Plonky2", "_refs/systems/plonky2-proof.rs",
     r"get_challenges\(\s*self\.get_public_inputs_hash\(\),\s*circuit_digest",
     "public-input hash and circuit digest enter challenge derivation"),
    ("Marlin", "_refs/marlin-lib.rs",
     r"FS::initialize\(\s*&to_bytes!\[&Self::PROTOCOL_NAME, &index_vk, &public_input\]",
     "protocol name, key, and public input seed the FS rng"),
    ("SP1", "_refs/systems/sp1-compressed.rs",
     r"PublicValuesMismatch",
     "public values are checked against the proof commitment"),
    ("Winterfell", "_refs/winterfell-verifier.rs",
     r"public_coin_seed\.append\(&mut pub_inputs\.to_elements\(\)\)",
     "public inputs are part of the coin seed"),
    ("Kimchi", "_refs/kimchi-verifier.rs",
     r"absorb_fq\(&\[verifier_index_digest\]\)",
     "verifier index digest absorbed first"),
    ("Barretenberg", "_refs/systems/bb-oink-verifier.cpp",
     r"receive_vk_hash_and_public_inputs",
     "verifier key hash and public inputs received via the transcript"),
    ("FastCrypto (missing domain)", "_refs/systems/fastcrypto.rs",
     r"TODO: Add domain seperation",
     "source acknowledges the missing domain separation"),
    ("FastCrypto (batching from c)", "_refs/systems/fastcrypto.rs",
     r"fiat_shamir_challenge\(&\(\"(?:mu|rho|alpha|beta)\", &c",
     "batching coefficients derived from the challenge only"),
    ("CIRCL (lossy encoding)", "_refs/systems/circl-qndleq-vuln.go",
     r"H\.Write\(g\.FillBytes\(nBytes\)\)",
     "pre-fix challenge hashes the absolute value"),
    ("Signal (difference only)", "_refs/systems/signal.rs",
     r"C_y\[second_point_index\] - self\.core\.attr_points\[second_point_index\]",
     "only the difference enters the transcript"),
]


def main() -> None:
    ok = 0
    for name, rel, pattern, why in CHECKS:
        path = ROOT / rel
        if not path.exists():
            print(f"MISSING  {name:<28} ({rel})")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found = re.search(pattern, text) is not None
        ok += found
        print(f"{'OK  ' if found else 'FAIL'}     {name:<28} {why}")

    print(f"\n{ok}/{len(CHECKS)} evidence lines found")
    sys.exit(0 if ok == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
