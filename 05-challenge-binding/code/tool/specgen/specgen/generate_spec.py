#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从源码生成规格骨架。

动机
----
M8 发现：3 个手写规格里有 3 个转写错误。手写本身就是错误源。
更可靠的做法是：能从源码机械抽取的系统，直接**生成**规格，而不是事后比对。

本脚本输出 monitor.py 格式的事件列表（Python 字面量）。人工只需补两件事：
  - `pc`（哪些是 prover 可控）
  - `check`（每个 challenge 负责哪条方程）

用法
----
python generate_spec.py FILE [--lang go|js|rust] [--indent 4]
"""

import argparse
import re
import sys
from pathlib import Path

RULES = {
    "go": [
        ("reset", re.compile(r"\b(?:fs|transcript)\.Reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\b(?:fs|transcript)\.Bind\s*\(\s*[^,]+,\s*(.+?)\)\s*[;{]")),
        ("squeeze", re.compile(r"\b(?:fs|transcript)\.ComputeChallenge\s*\(\s*[^)]*?\)")),
    ],
    "js": [
        ("reset", re.compile(r"\btranscript\.reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\btranscript\.(?:addPolCommitment|addScalar|append\w*)\s*\(\s*(.+?)\s*\)\s*;")),
        ("squeeze", re.compile(r"\bres\.(\w+)(?:\[\d+\])?\s*=\s*transcript\.getChallenge\s*\(\s*\)")),
    ],
    "rust": [
        ("reset", re.compile(r"\.reset\s*\(\s*\)")),
        ("absorb", re.compile(r"\.(?:absorb|absorb_in_ro|append_\w+|observe\w*|common_point|common_scalar|reseed)\s*\(\s*(.+?)\s*\)\s*[;?]")),
        # 允许 squeeze(N, false) 这类多参调用；有带标签的 challenge 时取标签
        ("squeeze", re.compile(r"\.(?:challenge\w*|get_challenge|squeeze\w*)\s*\(\s*(?:b?\"(\w+)\")?[^)]*\)")),
        # Winterfell 风格：public_coin.draw()
        ("squeeze", re.compile(r"\.draw\s*\(\s*\)")),
        # Plonky3 风格：challenger.sample_bits(...) / sample(...)
        ("squeeze", re.compile(r"\.sample\w*\s*\([^)]*\)")),
        # Marlin 风格：u128::rand(&mut fs_rng)
        ("squeeze", re.compile(r"\b\w+::rand\s*\(\s*&mut\s+fs_rng\s*\)")),
    ],
    "cpp": [
        ("reset", re.compile(r"->reset\s*\(\s*\)")),
        ("absorb", re.compile(r"->(?:send_to_verifier|receive_from_prover|add_to_hash_buffer)\s*(?:<[^>]*>)?\s*\(\s*(?:\"(\w+)\")?")),
        ("squeeze", re.compile(r"->(?:get_challenge|get_challenges|get_short_challenges|get_dyadic_powers_of_challenge)\s*(?:<[^>]*>)?\s*\(")),
    ],
}


def last_ident(expr: str, strip_methods: bool = False) -> str:
    """从表达式里取最能代表值的标识符。

    strip_methods=True 时先剥掉尾部的 .Method(...) 调用链，避免把 Marshal 之类的方法名
    当字段名（Go/C++ 常见）。JS/Rust 不能剥，否则 Fr.e(publicSignals[i]) 会退化成 Fr。
    """
    expr = expr.strip()
    if strip_methods:
        while True:
            m = re.search(r"\.[A-Za-z_]\w*\s*\([^()]*\)\s*$", expr)
            if not m:
                break
            expr = expr[: m.start()]

    idents = re.findall(r"[A-Za-z_]\w*", expr)
    if not idents:
        return "arg"
    # 取最后一个不是常见包装函数名的标识符
    wrappers = {"e", "i", "Fr", "Sc", "Scalar", "from", "as", "b"}
    cand = [i for i in idents if i not in wrappers]
    return cand[-1] if cand else idents[-1]


def guess_lang(path: str) -> str:
    return {
        ".go": "go", ".js": "js", ".ts": "js", ".rs": "rust",
        ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
    }.get(Path(path).suffix, "go")


def generate(path: str, lang: str):
    text = Path(path).read_text(encoding="utf-8")
    events = []
    for lineno, line in enumerate(text.splitlines(), 1):
        # 跳过函数定义行：trait/impl 里的方法签名不是调用点
        if re.search(r"\bfn\s+\w+", line):
            continue
        for kind, pat in RULES[lang]:
            m = pat.search(line)
            if not m:
                continue
            if kind == "reset":
                events.append(("reset", "", []))
            elif kind == "squeeze":
                name = m.group(1) if (lang in ("js", "rust") and m.groups() and m.group(1)) else "challenge"
                events.append(("squeeze", name, []))
            else:
                arg = m.group(1) if m.groups() and m.group(1) else "arg"
                name = "arg" if arg == "arg" else last_ident(arg, strip_methods=lang in ("go", "cpp"))
                events.append(("absorb", "a", [name]))
            break
    return events


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--lang", default=None)
    ap.add_argument("--indent", type=int, default=4)
    args = ap.parse_args()

    lang = args.lang or guess_lang(args.file)
    events = generate(args.file, lang)

    print(f"# generated from {args.file} (lang={lang})")
    print("events = [")
    for e in events:
        pad = " " * args.indent
        print(f"{pad}{e!r},")
    print("]")
    n_abs = sum(1 for e in events if e[0] == "absorb")
    n_sq = sum(1 for e in events if e[0] == "squeeze")
    print(f"# absorbs={n_abs} squeezes={n_sq}", file=sys.stderr)


if __name__ == "__main__":
    main()
