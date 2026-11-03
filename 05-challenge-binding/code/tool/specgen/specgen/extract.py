#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
specgen：从源码中启发式抽取 Fiat–Shamir transcript 事件序列。

动机
----
手工转写规格是当前方法的瓶颈（~10 分钟/系统），也是规模化的障碍。
不是所有系统都能自动抽取：
  - 显式 transcript API（snarkjs、gnark）→ 可以按调用顺序抽取；
  - 一次性哈希序列化元组（FastCrypto、Signal）→ 吸收结构不在调用序列里，需人工。

本脚本处理前者，并明确报告"抽取失败"的情况，避免假装自动化。

用法
----
python extract.py FILE [--lang go|js|rust|auto]
"""

import re
import sys
from dataclasses import dataclass, field

RULES = {
    "go": [
        ("reset", re.compile(r"\b(?:fs|transcript)\.Reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\b(?:fs|transcript)\.Bind\s*\(")),
        ("squeeze", re.compile(r"\b(?:fs|transcript)\.ComputeChallenge\s*\(")),
    ],
    "js": [
        ("reset", re.compile(r"\btranscript\.reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\btranscript\.(?:addPolCommitment|addScalar|append\w*)\s*\(")),
        ("squeeze", re.compile(r"\btranscript\.(?:getChallenge|challenge\w*)\s*\(")),
    ],
    "rust": [
        ("reset", re.compile(r"\.reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\.(?:absorb|absorb_in_ro|append_\w+|observe\w*|common_point|common_scalar)\s*\(")),
        ("squeeze", re.compile(r"\.(?:challenge\w*|get_challenge|squeeze\w*)\s*\(")),
    ],
}


@dataclass
class Event:
    line: int
    kind: str
    text: str


def guess_lang(path: str) -> str:
    for ext, lang in ((".go", "go"), (".js", "js"), (".ts", "js"), (".rs", "rust")):
        if path.endswith(ext):
            return lang
    return "auto"


def extract(path: str, lang: str) -> tuple[list[Event], int]:
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    rules = RULES[lang]
    events: list[Event] = []
    for i, line in enumerate(lines, 1):
        for kind, pat in rules:
            if pat.search(line):
                events.append(Event(i, kind, line.strip()[:120]))
                break
    return events, len(lines)


def summarize(events: list[Event]) -> str:
    if not events:
        return "  (no transcript events found)"
    out = []
    round_no = 0
    for e in events:
        if e.kind == "reset":
            round_no += 1
            out.append(f"  --- round {round_no} ---")
        else:
            out.append(f"  L{e.line:<5} {e.kind:<8} {e.text}")
    return "\n".join(out)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    lang = "auto"
    if "--lang" in sys.argv:
        lang = sys.argv[sys.argv.index("--lang") + 1]
    if lang == "auto":
        lang = guess_lang(path)

    events, total = extract(path, lang)
    n_absorb = sum(1 for e in events if e.kind == "absorb")
    n_squeeze = sum(1 for e in events if e.kind == "squeeze")
    n_reset = sum(1 for e in events if e.kind == "reset")

    print(f"file: {path}  lang: {lang}  lines: {total}")
    print(f"events: absorb={n_absorb} squeeze={n_squeeze} reset={n_reset}")
    print(summarize(events))

    if n_squeeze == 0:
        print("\n[WARN] 未发现 challenge 派生调用：该系统可能一次性哈希序列化元组，需人工转写。")
    if n_absorb == 0:
        print("\n[WARN] 未发现吸收调用：抽取失败。")


if __name__ == "__main__":
    main()
