#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Binding-check synthesis for checks whose randomness is a linear form.

Two families of batched checks share one decision problem:

  SPDZ-style MAC check        shares and MACs computed from the same values      (bound)
  MASCOT-style input check    shares sent, MACs/masked value computed separately (missing binding)

A missing-binding check passes for *any* deviation e between the shares and the values the
MACs attest. The later check that opens the element accepts iff the deviation cancels in the
linear form the check uses, i.e. sum_i m_i e_i = 0, where m is the mask/coefficient vector.
The element is therefore attackable iff

  (1) the first check does not bind (missing binding), and
  (2) a nonzero kernel vector of the linear form exists whose support is inside the
      positions the adversary controls.

With one opened value, (2) fails: m_1 e_1 = 0 forces e_1 = 0, so the check binds. With two or
more, it succeeds. This script decides (2), and reports it together with (1), for either a
prime field or Z_{2^m}.

Usage:
    python binding.py --masks 45747,6372 --field 65519
    python binding.py --masks 45747,6372 --field 65519 --missing-binding false
    python binding.py --masks 123,456,789,1011 --ring-exponent 128 --positions 2,3
"""

from __future__ import annotations

import argparse
import json
import math
import sys


def solve_field(m: list[int], positions: list[int], p: int) -> list[int] | None:
    a, b = positions[0], positions[1]
    if m[a] % p == 0 and m[b] % p == 0:
        return None
    if m[b] % p != 0:
        e_a = m[b] % p          # e = (m_b, -m_a) is a kernel vector
        e_b = (-m[a]) % p
    else:
        e_a = 1                 # m_a != 0: e = (1, 0) is a kernel vector
        e_b = 0
    kernel = [0] * len(m)
    kernel[a], kernel[b] = e_a, e_b
    return kernel


def solve_ring(m: list[int], positions: list[int], mod: int) -> list[int] | None:
    a, b = positions[0], positions[1]
    g = math.gcd(math.gcd(m[a], m[b]), mod)
    if g == 0:
        return None
    e_a = ((-m[b]) // g) % mod
    e_b = ((m[a]) // g) % mod
    kernel = [0] * len(m)
    kernel[a], kernel[b] = e_a, e_b
    return kernel


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--masks", required=True, help="comma-separated check coefficients/masks")
    ap.add_argument("--field", type=int, help="prime field modulus")
    ap.add_argument("--ring-exponent", type=int, help="ring is Z_{2^m}")
    ap.add_argument("--positions", default="last", help="'last', 'all', or indices")
    ap.add_argument("--missing-binding", default="true",
                    help="true if the first check does not bind shares to MACs")
    ap.add_argument("--json")
    args = ap.parse_args()

    masks = [int(x) for x in args.masks.split(",")]
    if args.positions == "all":
        positions = list(range(len(masks)))
    elif args.positions == "last":
        positions = [len(masks) - 2, len(masks) - 1]
    else:
        positions = [int(x) for x in args.positions.split(",")]
    if len(masks) < 2 or len(positions) < 2:
        print(json.dumps({
            "attackable": False,
            "reason": "fewer than two controlled positions; m_1 e_1 = 0 forces e_1 = 0",
            "residual": None,
        }, indent=2))
        return 1 if args.missing_binding.lower() == "true" else 0

    if args.field:
        mod = args.field
        kernel = solve_field(masks, positions, mod)
    elif args.ring_exponent:
        mod = 1 << args.ring_exponent
        kernel = solve_ring(masks, positions, mod)
    else:
        raise SystemExit("give --field or --ring-exponent")
    if kernel is None:
        print(json.dumps({"attackable": False, "reason": "no nonzero kernel vector"}, indent=2))
        return 1

    residual = sum(x * y for x, y in zip(masks, kernel)) % mod
    missing = args.missing_binding.lower() == "true"
    report = {
        "ring": f"F_{mod}" if args.field else f"Z_2^{args.ring_exponent}",
        "masks": masks,
        "positions": positions,
        "kernel_vector": kernel,
        "residual": residual,
        "missing_binding": missing,
        "attackable": missing and residual == 0 and any(x % mod for x in kernel),
        "changed_values": sum(1 for x in kernel if x % mod),
    }
    print(json.dumps(report, indent=2))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    return 0 if report["attackable"] else 1


if __name__ == "__main__":
    sys.exit(main())
