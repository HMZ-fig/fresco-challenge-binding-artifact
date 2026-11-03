#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
回归实验：用**生成**的规格替换手写规格，确认判定不变（snarkjs）。

生成的规格缺两类标注：
  - pc：哪些值 prover 可控
  - checks：每个 challenge 负责哪条方程

这两类由人工补，其余（吸收顺序、challenge 序列、轮次）来自源码。
若判定与手写版本一致，说明替换可行。
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "transcript_monitor"))

from generate_spec import generate  # noqa: E402
from monitor import Spec, analyze, snarkjs_plonk  # noqa: E402

SRC = r"D:\Projects\New\_refs\systems\snarkjs.js"

PC = {
    "Qm", "Ql", "Qr", "Qo", "Qc", "S1", "S2", "S3",
    "publicSignals", "A", "B", "C", "Z", "T1", "T2", "T3",
    "eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw",
    "Wxi", "Wxiw",
}

CHECKS = [
    ("beta", ["publicSignals", "A", "B", "C"]),
    ("gamma", ["beta"]),
    ("alpha", ["beta", "gamma", "Z"]),
    ("xi", ["alpha", "T1", "T2", "T3"]),
    ("v", ["xi", "eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"]),
    ("u", ["Wxi", "Wxiw"]),
]


def main() -> None:
    events = generate(SRC, "js")

    # 生成器把 reset 记作独立事件；Spec 直接接受同一格式
    events = events + [("check", c, args) for c, args in CHECKS]

    generated = Spec(name="snarkjs-generated", events=events, pc=PC, has_domain=False)

    hand = snarkjs_plonk()

    g = analyze(generated)
    h = analyze(hand)

    fmt = lambda vs: sorted((k, c, tuple(sorted(m))) for k, c, m in vs)
    print(f"generated violations: {fmt(g)}")
    print(f"hand      violations: {fmt(h)}")
    print(f"same verdict: {fmt(g) == fmt(h)}")


if __name__ == "__main__":
    main()
