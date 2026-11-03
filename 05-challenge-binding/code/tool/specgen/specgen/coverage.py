#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成器覆盖率实验：对语料中的每个系统运行 generate_spec，统计可抽取程度。

判据
----
- usable: 至少 1 个 absorb 与 1 个 squeeze，且 absorb 名称不是纯方法名
- partial: 有事件但名称可疑（如全是 Marshal / challenge）
- unusable: 无 squeeze 或无可识别事件
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_spec import generate  # noqa: E402

R = Path(r"D:\Projects\New\_refs")

SYSTEMS = [
    ("snarkjs", R / "systems/snarkjs.js", "js"),
    ("gnark-backend", R / "gnark/backend/plonk/bls12-381/verify.go", "go"),
    ("bulletproofs", R / "bulletproofs.rs", "rust"),
    ("nova", R / "nova-mod.rs", "rust"),
    ("marlin", R / "marlin-lib.rs", "rust"),
    ("plonky3", R / "systems/p3-fri-verifier.rs", "rust"),
    ("winterfell", R / "winterfell-verifier.rs", "rust"),
    ("kimchi", R / "kimchi-verifier.rs", "rust"),
    ("fastcrypto", R / "systems/fastcrypto.rs", "rust"),
    ("signal", R / "systems/signal.rs", "rust"),
    ("risc0", R / "systems/risc0-receipt.rs", "rust"),
    ("neutron", R / "systems/neutron.rs", "rust"),
    ("sp1", R / "sp1-lib.rs", "rust"),
    ("halo2", R / "systems/halo2-plonk-verifier.rs", "rust"),
    ("barretenberg", R / "systems/bb-oink-verifier.cpp", "cpp"),
    ("hypernova", R / "systems/bb-hypernova-verifier.cpp", "cpp"),
]

BAD_NAMES = {"Marshal", "challenge", "arg", "Sum", "Write"}


def classify(events):
    n_abs = sum(1 for e in events if e[0] == "absorb")
    n_sq = sum(1 for e in events if e[0] == "squeeze")
    names = {e[2][0] for e in events if e[0] == "absorb" and e[2]}
    if n_sq == 0 or n_abs == 0:
        return "unusable", n_abs, n_sq, names
    if names and names <= BAD_NAMES:
        return "partial", n_abs, n_sq, names
    return "usable", n_abs, n_sq, names


def main() -> None:
    rows = []
    for name, path, lang in SYSTEMS:
        if not path.exists():
            rows.append((name, "missing", 0, 0, set()))
            continue
        events = generate(str(path), lang)
        verdict, n_abs, n_sq, names = classify(events)
        rows.append((name, verdict, n_abs, n_sq, names))

    print(f"{'system':<14}{'verdict':<10}{'abs':>4}{'sq':>4}  names")
    for name, verdict, n_abs, n_sq, names in rows:
        sample = ", ".join(sorted(names)[:5])
        print(f"{name:<14}{verdict:<10}{n_abs:>4}{n_sq:>4}  {sample}")

    usable = sum(1 for r in rows if r[1] == "usable")
    partial = sum(1 for r in rows if r[1] == "partial")
    print(f"\nusable={usable}  partial={partial}  total={len(rows)}")


if __name__ == "__main__":
    main()
