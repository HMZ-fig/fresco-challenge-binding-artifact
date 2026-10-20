#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate the kernel test result lines shipped in runs/unpatched and runs/patched."""

import re
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULT = re.compile(r"(KERNEL\d*P?_RESULT|KERNEL_RESULT|K\d+[A-Z]*_RESULT)\s+([a-z]+)")


def scan(sub: str):
    per_file = {}
    for p in sorted((HERE / sub).glob("*.log")):
        lines = [f"{m.group(1)} {m.group(2)}" for m in RESULT.finditer(p.read_text(errors="replace"))]
        if lines:
            per_file[p.name] = lines
    return per_file


def main() -> None:
    out = []
    for sub, label in (("unpatched", "Unpatched tree"), ("patched", "Patched tree")):
        per_file = scan(sub)
        groups = defaultdict(Counter)
        for name, lines in per_file.items():
            key = re.sub(r"[-_]?\d*\.log$", "", name)
            for ln in lines:
                groups[key][ln] += 1
        out.append(f"## {label}\n")
        out.append(f"{len(per_file)} logs with result lines.\n")
        out.append("| Log group | Result | Count |")
        out.append("|---|---|---|")
        for key in sorted(groups):
            for result, count in sorted(groups[key].items()):
                out.append(f"| `{key}` | `{result}` | {count} |")
        out.append("")
    (HERE / "SUMMARY.md").write_text("# Kernel run summary\n\n" + "\n".join(out), encoding="utf-8")
    print("wrote", HERE / "SUMMARY.md")
    print("\n".join(out))


if __name__ == "__main__":
    main()
