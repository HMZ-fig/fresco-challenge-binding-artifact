#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规格-代码一致性检查。

对使用显式 transcript API 的系统，从源码抽取 challenge 的派生顺序与 reset 边界，
与 monitor.py 里的规格比对。一致说明规格在"调度"层面忠实于代码。

用法
----
python check_spec_consistency.py --system snarkjs
python check_spec_consistency.py --system bulletproofs --lines 340 420
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "transcript_monitor"
sys.path.insert(0, str(ROOT))
from monitor import snarkjs_plonk, bulletproofs, gnark_backend  # noqa: E402

SOURCES = {
    "snarkjs": r"D:\Projects\New\_refs\systems\snarkjs.js",
    "bulletproofs": r"D:\Projects\New\_refs\bulletproofs.rs",
    "gnark": r"D:\Projects\New\_refs\gnark\backend\plonk\bls12-381\verify.go",
}


def extract(text: str, system: str):
    if system == "snarkjs":
        labels = re.findall(r"res\.(\w+)(?:\[\d+\])?\s*=\s*transcript\.getChallenge\(\)", text)
        resets = len(re.findall(r"transcript\.reset\(\)", text))
        return labels, resets
    if system == "bulletproofs":
        # 只在 verifier 区间内抽取（同一文件里 prover 也用同名标签）
        labels = re.findall(r'challenge_scalar\(b"(\w+)"\)', text)
        return labels, 0
    if system == "gnark":
        # NewTranscript(hash, "gamma", "beta", "alpha", "zeta")
        line = next(l for l in text.splitlines() if "NewTranscript(" in l)
        labels = re.findall(r'"(\w+)"', line)
        return labels, 0
    raise ValueError(system)


def spec_schedule(spec):
    labels = [e[1] for e in spec.events if e[0] == "squeeze"]
    resets = sum(1 for e in spec.events if e[0] == "reset")
    return labels, resets


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", required=True, choices=list(SOURCES))
    ap.add_argument("--lines", nargs=2, type=int, default=None)
    args = ap.parse_args()

    lines = Path(SOURCES[args.system]).read_text(encoding="utf-8").splitlines()
    if args.lines:
        lines = lines[args.lines[0] - 1 : args.lines[1]]
    text = "\n".join(lines)

    src_labels, src_resets = extract(text, args.system)
    spec = {"snarkjs": snarkjs_plonk, "bulletproofs": bulletproofs, "gnark": gnark_backend}[args.system]()
    spec_labels, spec_resets = spec_schedule(spec)

    ok_labels = src_labels == spec_labels
    ok_rounds = src_resets + 1 == spec_resets + 1

    print(f"system: {args.system}")
    print(f"  source challenges ({len(src_labels)}): {src_labels}")
    print(f"  spec   challenges ({len(spec_labels)}): {spec_labels}")
    print(f"  source rounds: {src_resets + 1}   spec rounds: {spec_resets + 1}")
    print(f"  challenge sequence match: {ok_labels}")
    print(f"  round count match:        {ok_rounds}")
    sys.exit(0 if (ok_labels and ok_rounds) else 1)


if __name__ == "__main__":
    main()
