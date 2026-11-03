#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Artifact 入口：一次性复现论文中的全部实验。

每个条目运行一个脚本，检查输出中的期望标记或退出码，最后打印汇总表。
任何一项失败都会以非零码退出。
"""

import os
import subprocess
import sys
from pathlib import Path

# Force UTF-8 on both sides: the cases print non-ASCII text, and a default
# Windows console is cp1252, which would crash the harness before it reports.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

CHILD_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}

ROOT = Path(__file__).resolve().parent.parent

CASES = [
    {
        "name": "checker: weak vs strong Schnorr",
        "cmd": [sys.executable, str(ROOT / "tool/transcript_monitor/monitor.py")],
        "expect": ["VIOLATION B1-coverage: 'c' 未绑定 ['x']", "[strong-schnorr]", "OK"],
    },
    {
        "name": "checker: mutation test",
        "cmd": [sys.executable, str(ROOT / "tool/transcript_monitor/mutation_test.py")],
        "expect": ["false positives): 0", "false negatives): 0"],
    },
    {
        "name": "specgen: coverage",
        "cmd": [sys.executable, str(ROOT / "tool/specgen/coverage.py")],
        "expect": ["usable=9"],
    },
    {
        "name": "spec consistency: snarkjs",
        "cmd": [sys.executable, str(ROOT / "tool/specgen/check_spec_consistency.py"), "--system", "snarkjs"],
        "expect": ["challenge sequence match: True"],
    },
    {
        "name": "spec consistency: bulletproofs",
        "cmd": [sys.executable, str(ROOT / "tool/specgen/check_spec_consistency.py"), "--system", "bulletproofs", "--lines", "340", "420"],
        "expect": ["challenge sequence match: True"],
    },
    {
        "name": "spec consistency: gnark",
        "cmd": [sys.executable, str(ROOT / "tool/specgen/check_spec_consistency.py"), "--system", "gnark"],
        "expect": ["challenge sequence match: True"],
    },
    {
        "name": "regression: generated vs hand spec",
        "cmd": [sys.executable, str(ROOT / "tool/specgen/regression_snarkjs.py")],
        "expect": ["same verdict: True"],
    },
    {
        "name": "attribution sensitivity",
        "cmd": [sys.executable, str(ROOT / "tool/attribution_sensitivity.py")],
        "expect": ["59/129"],
    },
    {
        "name": "annotation sensitivity",
        "cmd": [sys.executable, str(ROOT / "tool/annotation_sensitivity.py")],
        "expect": ["single annotation point of failure"],
    },
    {
        "name": "evidence lines present in pinned sources",
        "cmd": [sys.executable, str(ROOT / "artifact/check_evidence_lines.py")],
        "expect": ["14/14 evidence lines found"],
    },
    {
        "name": "figure/table consistency",
        "cmd": [sys.executable, str(ROOT / "tool/audit_figures.py")],
        "expect": ["compared 19 rows"],
    },
    {
        "name": "numeric consistency (draft vs table)",
        "cmd": [sys.executable, str(ROOT / "tool/audit_numbers.py")],
        "expect": ["three of the thirteen"],
    },
    {
        "name": "data-driven specs",
        "cmd": [sys.executable, str(ROOT / "artifact/run_specs.py")],
        "expect": ["26/26 specs match expectation"],
    },
    {
        "name": "poc: weak Fiat-Shamir forgery",
        "cmd": [sys.executable, str(ROOT / "poc/weak_fs_schnorr.py")],
        "expect": ["伪造验证: True", "伪造验证: False"],
    },
    {
        "name": "poc: length-prefix injectivity",
        "cmd": [sys.executable, str(ROOT / "poc/length_prefix_injectivity.py")],
        "expect": ["injective over sample messages: True"],
    },
    {
        "name": "poc: snarkjs encoding ambiguity",
        "cmd": [sys.executable, str(ROOT / "poc/snarkjs_encoding_ambiguity.py")],
        "expect": ["challenge equal: True"],
    },
    {
        "name": "poc: CIRCL challenge collision",
        "cmd": [sys.executable, str(ROOT / "poc/circl_qndleq_collision.py")],
        "expect": ["collision: True"],
    },
    {
        "name": "poc: FastCrypto batching attack",
        "cmd": [sys.executable, str(ROOT / "poc/fastcrypto_batching_attack.py")],
        "expect": ["attack succeeds: True", "attack succeeds: False"],
    },
]


REQUIRED = [
    "_refs/systems/snarkjs.js",
    "_refs/gnark/backend/plonk/bls12-381/verify.go",
    "_refs/bulletproofs.rs",
    "_refs/systems/p3-fri-verifier.rs",
    "_refs/systems/halo2-plonk-verifier.rs",
]


def preflight() -> bool:
    missing = [p for p in REQUIRED if not (ROOT / p).exists()]
    if missing:
        print("missing source snapshots:")
        for p in missing:
            print(f"  {p}")
        print("\nrun:  powershell -ExecutionPolicy Bypass -File artifact/fetch_sources.ps1")
        return False
    return True


def run_case(case):
    try:
        proc = subprocess.run(
            case["cmd"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=180,
            env=CHILD_ENV,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout", ""

    out = (proc.stdout or "") + (proc.stderr or "")
    missing = [m for m in case["expect"] if m not in out]
    ok = (not missing) and proc.returncode == 0
    if missing:
        detail = f"missing: {missing}"
    elif proc.returncode != 0:
        detail = f"exit code {proc.returncode}"
    else:
        detail = ""
    return ok, detail, out


def main() -> None:
    if not preflight():
        sys.exit(2)

    rows = []
    for case in CASES:
        ok, detail, out = run_case(case)
        rows.append((case["name"], ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {case['name']}")
        if not ok:
            print(f"       {detail}")
            print("       ---- output tail ----")
            for line in out.splitlines()[-8:]:
                print(f"       {line}")

    n_pass = sum(1 for _, ok, _ in rows if ok)
    print(f"\nsummary: {n_pass}/{len(rows)} passed")
    sys.exit(0 if n_pass == len(rows) else 1)


if __name__ == "__main__":
    main()









