# -*- coding: utf-8 -*-
"""
检查器的变异测试：量化假阳性（benign 变异被报）与假阴性（harmful 变异漏报）。

思路
----
取一组"已知正确"的规格作为种子，对它们做两类单点变异：
- benign：语义保持（重复吸收、增加无关常量、拆分吸收、交换独立的吸收顺序）
- harmful：语义破坏（删除必需吸收、把吸收移到 squeeze 之后、把值替换成派生值）

一个合格的检查器应当：benign 全部不报，harmful 全部报出。
"""

import sys

from monitor import Spec, analyze


def required_map(spec: Spec):
    """复刻 analyze 的 Required 计算，用于判断某个值是否必需。"""
    req = {c: set() for c in spec.challenges}
    for kind, label, args in spec.events:
        if kind != "check":
            continue
        c = label
        req[c] |= (set(args) & spec.pc) - spec.post.get(c, set()) - {c}
    return req


def has_violation(spec: Spec) -> bool:
    return any(v[0].startswith("B1") for v in analyze(spec))


def clone(spec: Spec, events) -> Spec:
    return Spec(
        name=spec.name,
        events=events,
        pc=set(spec.pc),
        post={k: set(v) for k, v in spec.post.items()},
        has_domain=spec.has_domain,
        constraint_bound=set(spec.constraint_bound),
    )


def benign_mutants(spec: Spec):
    out = []
    ev = spec.events
    for i, (kind, label, args) in enumerate(ev):
        if kind != "absorb":
            continue
        # 1. 重复吸收
        out.append((f"{spec.name}:dup-absorb-{i}", clone(spec, ev[: i + 1] + [ev[i]] + ev[i + 1 :])))
        # 2. 增加无关常量
        out.append((f"{spec.name}:add-const-{i}", clone(spec, ev[: i + 1] + [("absorb", "const", ["CONST"])] + ev[i + 1 :])))
        # 3. 拆分吸收
        if len(args) >= 2:
            split = [("absorb", label + "a", args[:1]), ("absorb", label + "b", args[1:])]
            out.append((f"{spec.name}:split-absorb-{i}", clone(spec, ev[:i] + split + ev[i + 1 :])))
    # 4. 交换相邻的独立吸收
    for i in range(len(ev) - 1):
        if ev[i][0] == "absorb" and ev[i + 1][0] == "absorb":
            out.append((f"{spec.name}:swap-{i}", clone(spec, ev[:i] + [ev[i + 1], ev[i]] + ev[i + 2 :])))
    return out


def harmful_mutants(spec: Spec):
    out = []
    ev = spec.events
    req = required_map(spec)
    required_values = set().union(*req.values()) if req else set()

    for i, (kind, label, args) in enumerate(ev):
        if kind != "absorb":
            continue
        hit = set(args) & required_values
        if not hit:
            continue
        # 1. 删除吸收
        out.append((f"{spec.name}:drop-absorb-{i}({sorted(hit)})", clone(spec, ev[:i] + ev[i + 1 :])))
        # 2. 移到 squeeze 之后
        tail = ev[i + 1 :] + [ev[i]]
        out.append((f"{spec.name}:move-after-{i}({sorted(hit)})", clone(spec, ev[:i] + tail)))
        # 3. 替换为派生值
        derived = [("absorb", label, ["derived_" + a if a in hit else a for a in args])]
        out.append((f"{spec.name}:derive-{i}({sorted(hit)})", clone(spec, ev[:i] + derived + ev[i + 1 :])))
    return out


def main() -> None:
    # 种子：已知正确的规格
    from monitor import (
        strong_schnorr,
        _phantom,
        circl_qndleq,
        signal_zkcredential,
        halo2_vk,
        plonky3,
    )

    seeds = [
        strong_schnorr(),
        _phantom(True),
        circl_qndleq(False),
        signal_zkcredential(False),
        halo2_vk(False),
        plonky3(True),
    ]

    benign, harmful = [], []
    for s in seeds:
        benign += benign_mutants(s)
        harmful += harmful_mutants(s)

    fp = [(n, s) for n, s in benign if has_violation(s)]
    fn = [(n, s) for n, s in harmful if not has_violation(s)]

    print(f"seeds: {len(seeds)}")
    print(f"benign mutants: {len(benign)}, flagged (false positives): {len(fp)}")
    print(f"harmful mutants: {len(harmful)}, missed (false negatives): {len(fn)}")
    if benign:
        print(f"specificity: {100 * (1 - len(fp) / len(benign)):.1f}%")
    if harmful:
        print(f"sensitivity: {100 * (1 - len(fn) / len(harmful)):.1f}%")

    if fp:
        print("\n--- false positives ---")
        for n, _ in fp[:20]:
            print(" ", n)
    if fn:
        print("\n--- false negatives ---")
        for n, _ in fn[:20]:
            print(" ", n)


if __name__ == "__main__":
    main()
