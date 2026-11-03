#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Automated kernel-vector synthesis for batched consistency checks over Z_{2^m}.

Given the modulus exponent m, the low-value bit length k, a coefficient vector r and
the positions a corrupt party can tamper with, this finds a tampering vector e with

    sum_i r_i * e_i == 0  (mod 2^m)

such that at least two opened low parts change, i.e. e_i mod 2^k != 0 for at least two
tampered positions. This is exactly the acceptance condition of a SPDZ-style batched MAC
check when the coefficients are known before the errors are chosen.

Usage:
    python synth.py --coeffs 123,456,789,1011 --m 128 --k 64 --positions 2,3
    python synth.py --log run.log --k 64 --positions 4,5
    python synth.py --log run.log --k 64 --json report.json

The script writes a reproducible report (kernel vector, residual, low-part deltas, kernel
multiplicity) and exits 1 if no two-position tamper exists.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path


def read_log(path: Path) -> str:
    raw = path.read_bytes()
    if b"\x00" in raw[:2000]:
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def parse_coeffs_log(path: Path) -> list[int]:
    text = read_log(path)
    m = re.search(r"coeffs=\[([^\]]+)\]", text)
    if not m:
        raise SystemExit(f"no coeffs=[...] line in {path}")
    return [int(x) for x in re.split(r"[,\s]+", m.group(1).strip()) if x]


def solve_two(r_a: int, r_b: int, mod: int) -> tuple[int, int] | None:
    """Return (e_a, e_b) with r_a e_a + r_b e_b == 0 (mod mod), both nonzero mod 2^k
    is checked by the caller. Uses e_a = -r_b/g, e_b = r_a/g with g = gcd(r_a, r_b, mod)."""
    g = math.gcd(math.gcd(r_a, r_b), mod)
    if g == 0:
        return None
    e_a = (-r_b // g) % mod
    e_b = (r_a // g) % mod
    if (r_a * e_a + r_b * e_b) % mod != 0:
        return None
    return e_a, e_b


def kernel_multiplicity(r: int, mod: int) -> int:
    """Smallest nonzero kernel element of the map e -> r*e over Z_mod: 2^{m - v2(r)} etc."""
    if r == 0:
        return 1
    v = (r & -r).bit_length() - 1
    return 1 << max(0, (mod.bit_length() - 1) - v)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--coeffs", help="comma-separated coefficients")
    ap.add_argument("--log", type=Path, help="log file containing coeffs=[...]")
    ap.add_argument("--m", type=int, default=128, help="ring modulus exponent (2^m)")
    ap.add_argument("--k", type=int, default=64, help="low-value bit length")
    ap.add_argument("--positions", default="last", help="'last', 'all', or comma-separated indices")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    if args.log:
        coeffs = parse_coeffs_log(args.log)
    elif args.coeffs:
        coeffs = [int(x) for x in args.coeffs.split(",")]
    else:
        raise SystemExit("give --coeffs or --log")
    mod = 1 << args.m
    k = args.k

    if args.positions == "all":
        positions = list(range(len(coeffs)))
    elif args.positions == "last":
        positions = [len(coeffs) - 2, len(coeffs) - 1]
    else:
        positions = [int(x) for x in args.positions.split(",")]
    if len(positions) < 2:
        raise SystemExit("need at least two tampered positions")

    a, b = positions[0], positions[1]
    sol = solve_two(coeffs[a], coeffs[b], mod)
    if sol is None:
        print("no two-position kernel vector", file=sys.stderr)
        return 1
    e = [0] * len(coeffs)
    e[a], e[b] = sol

    residual = sum(r * x for r, x in zip(coeffs, e)) % mod
    low = [x % (1 << k) for x in e]
    changed = [i for i in positions if low[i] != 0]
    report = {
        "modulus_exponent": args.m,
        "low_bits": k,
        "coefficients": coeffs,
        "positions": positions,
        "kernel_vector": e,
        "residual": residual,
        "low_part_deltas": {str(i): low[i] for i in positions},
        "changed_low_parts": changed,
        "accepted": residual == 0,
        "output_changed": len(changed) >= 2,
        "kernel_multiplicity_at_a": kernel_multiplicity(coeffs[a] % mod, mod),
    }
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["accepted"] and report["output_changed"] else 1


if __name__ == "__main__":
    sys.exit(main())
