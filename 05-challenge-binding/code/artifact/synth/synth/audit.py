#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static audit: where do batched-check coefficients come from?

Classifies Java sources that contain a MAC-check implementation by the source of the
combining coefficients:

  SAFE_FRESH   the check itself runs a coin toss / builds a fresh generator
  CANDIDATE    coefficients are taken from a generator/seed established before the check
  OTHER        check found, coefficient source not recognized

The rules are textual and deliberately conservative; every hit must be read by a human.
This is the automated part of the C2 (randomness ordering) audit in the paper.

Usage:
    python audit.py --src path/to/java/src [--src ...] [--json report.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CHECK = re.compile(r"MacCheck|doMacCheck|MacCheckComputation", re.I)
FRESH = re.compile(r"CoinTossing|createRandomGenerator|freshJointSeed|CoinTossingComputation", re.I)
SETUP = re.compile(r"initializeJointRandomness|getRandomGenerator|getJointRandomGenerator|jointSeed", re.I)


def classify(path: Path) -> dict | None:
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    if not CHECK.search(text):
        return None
    if not re.search(r"coefficient|drbg|getRandom|randomness", text, re.I):
        return None
    fresh_lines = [i + 1 for i, ln in enumerate(lines) if FRESH.search(ln)]
    setup_lines = [i + 1 for i, ln in enumerate(lines) if SETUP.search(ln)]
    if fresh_lines:
        verdict = "SAFE_FRESH"
        evidence = fresh_lines[:5]
    elif setup_lines:
        verdict = "CANDIDATE"
        evidence = setup_lines[:5]
    else:
        verdict = "OTHER"
        evidence = []
    return {
        "file": str(path),
        "verdict": verdict,
        "evidence_lines": evidence,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", action="append", required=True, type=Path, help="java source root")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    results = []
    for root in args.src:
        for path in sorted(root.rglob("*.java")):
            try:
                r = classify(path)
            except Exception:
                continue
            if r:
                results.append(r)

    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        ev = ",".join(str(x) for x in r["evidence_lines"]) or "-"
        print(f"{r['verdict']:10} {r['file']}  lines {ev}")
    print(f"\nsummary: {counts}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0 if counts.get("CANDIDATE") is not None else 1


if __name__ == "__main__":
    sys.exit(main())
