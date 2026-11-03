#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 monitor.py 里的规格导出为 JSON 数据文件，并做往返一致性检验。

导出后 artifact 的规格是独立数据，不再与检查器代码耦合；
加载回来重跑判定，若与原判定一致，说明序列化无损。
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "transcript_monitor"))

from monitor import (  # noqa: E402
    Spec, analyze,
    weak_schnorr, strong_schnorr, _phantom,
    snarkjs_plonk, fastcrypto_kcp, fastcrypto_kcp_fixed, circl_qndleq, signal_zkcredential,
    marlin, barretenberg_oink, winterfell, kimchi, gnark_std, halo2, dusk_plonk, jellyfish_plonk, cl_signatures,
    halo2_vk, plonky3, bulletproofs, gnark_backend,
)

OUT = HERE.parent.parent / "artifact" / "specs"


def registry():
    return [
        weak_schnorr(), strong_schnorr(),
        _phantom(False), _phantom(True),
        snarkjs_plonk(), fastcrypto_kcp(), fastcrypto_kcp_fixed(),
        circl_qndleq(True), circl_qndleq(False),
        signal_zkcredential(True), signal_zkcredential(False),
        halo2_vk(True), halo2_vk(False),
        plonky3(True), plonky3(False),
        bulletproofs(), gnark_backend(), marlin(), barretenberg_oink(), winterfell(), kimchi(), gnark_std(), halo2(), dusk_plonk(), jellyfish_plonk(), cl_signatures(),
    ]


def to_dict(s: Spec) -> dict:
    return {
        "name": s.name,
        "events": [list(e) for e in s.events],
        "pc": sorted(s.pc),
        "post": {k: sorted(v) for k, v in s.post.items()},
        "has_domain": s.has_domain,
        "constraint_bound": sorted(s.constraint_bound),
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


def signature(violations):
    return sorted((k, c, tuple(sorted(m))) for k, c, m in violations)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ok = 0
    total = 0
    for spec in registry():
        total += 1
        data = to_dict(spec)
        path = OUT / f"{spec.name}.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        reloaded = from_dict(json.loads(path.read_text(encoding="utf-8")))
        same = signature(analyze(spec)) == signature(analyze(reloaded))
        ok += same
        print(f"{'OK  ' if same else 'DIFF'} {spec.name}")

    print(f"\nround-trip: {ok}/{total}")


if __name__ == "__main__":
    main()




