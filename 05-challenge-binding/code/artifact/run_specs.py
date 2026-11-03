#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据驱动地运行全部规格：从 artifact/specs/*.json 加载，跑 B1 判定，
与期望（有/无覆盖违规）比对。

这把"检查器 + 规格数据"解耦，审稿人可以只改 JSON 就复现或扩展。
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tool" / "transcript_monitor"))

from monitor import Spec, analyze  # noqa: E402

SPECS = HERE / "specs"

# 期望：True = 应报出 B1 覆盖违规；False = 不应报
EXPECTED = {
    "weak-schnorr": True,
    "strong-schnorr": False,
    "phantom-buggy": True,
    "phantom-fixed": False,
    "snarkjs-plonk": False,
    "fastcrypto-kcp": True,
    "fastcrypto-kcp-fixed": False,
    "circl-qndleq-vuln": True,
    "circl-qndleq-fixed": False,
    "signal-zkcred-vuln": True,
    "signal-zkcred-fixed": False,
    "halo2-vk-missing": True,
    "halo2-vk-bound": False,
    "plonky3-constraint-bound": False,
    "plonky3-unbound": True,
    "bulletproofs": False,
    "marlin": False,
    "barretenberg-oink": False,
    "winterfell": False,
    "kimchi": False,
    "gnark-std": False,
    "halo2": False,
    "dusk-plonk": False,
    "jellyfish-plonk": False,
    "cl-signatures": False,
    "gnark-backend": False,
}


def from_dict(d: dict) -> Spec:
    return Spec(
        name=d["name"],
        events=[tuple(e) for e in d["events"]],
        pc=set(d["pc"]),
        post={k: set(v) for k, v in d["post"].items()},
        has_domain=d["has_domain"],
        constraint_bound=set(d["constraint_bound"]),
    )


def has_b1(spec: Spec) -> bool:
    return any(v[0].startswith("B1") for v in analyze(spec))


def main() -> None:
    files = sorted(SPECS.glob("*.json"))
    ok = 0
    for path in files:
        spec = from_dict(json.loads(path.read_text(encoding="utf-8")))
        got = has_b1(spec)
        want = EXPECTED.get(spec.name)
        good = got == want
        ok += good
        print(f"{'OK  ' if good else 'FAIL'} {spec.name:<28} b1={got} expected={want}")

    print(f"\n{ok}/{len(files)} specs match expectation")
    sys.exit(0 if ok == len(files) else 1)


if __name__ == "__main__":
    main()




