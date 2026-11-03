#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OrderTool v0.2 — ordering analysis for consistency checks.

Improvements over v0.1:
  * more randomness idioms (C++/Java/Rust/Python)
  * call graph depth 2
  * field provenance: constructor assignments of DRBG fields are traced
  * hash-based checks reported separately (C1-ish / different mechanism)
"""

import argparse
import csv
import re
from pathlib import Path

EXTS = {".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".rs", ".py", ".go"}

CHECK_NAME = re.compile(r"(\w*(?:check|verify|mac|consistency|sacrifice|audit|validate)\w*)", re.I)

RANDOM = [
    (re.compile(r"getRandomGenerator\s*\("), "pool-getter"),
    (re.compile(r"\bget_random\s*\(|\bgetRandom\s*\(|get_random_long|randomizer\.get|internal\.get_random"), "shared-getter"),
    (re.compile(r"\bthis->drbg\b|\bthis\.drbg\b|\bself\.drbg\b"), "drbg-field"),
    (re.compile(r"\bdrbg\b", re.I), "drbg-field"),
    (re.compile(r"Create_Random_Seed|Create_Random\s*\(|Random_Seed|create_random"), "coin-toss"),
    (re.compile(r"sampleRandom|sample_random|sample_randomness"), "coin-toss"),
    (re.compile(r"CoinTossing|CoinToss|coin_toss|cointoss", re.I), "coin-toss"),
    (re.compile(r"genPrss|GenPrss|fillPrss|Prss\(|PRSS"), "prss"),
    (re.compile(r"get_shared_randomness|shared_randomness|get_authenticated_randomness"), "coin-toss"),
    (re.compile(r"commit_reveal|commit_and_open|Commit_And_Open|commit_and_reveal"), "coin-toss"),
    (re.compile(r"new\s+AesCtrDrbg|AesCtrDrbg\(|AesCtrDrbgFactory|fromDerivedSeed"), "local-drbg"),
    (re.compile(r"new\s+SecureRandom|SecureRandom\(\)|secrets\.|os\.urandom"), "local-rng"),
    (re.compile(r"thread_rng|OsRng|rand::|rand\(\)|random_device"), "local-rng"),
    (re.compile(r"Prp\(|PrpFactory|PrpUtils"), "local-prp"),
]

HASH = re.compile(r"\bhash\b|\bSha|SHA-?\d|\bcommitment\b|\bCommitment\b|hmac|HMAC", re.I)

MESSAGE = re.compile(
    r"send_data|recv_data|sendToAll|receiveFromAll|send_receive|send_relative|"
    r"pass_around|broadcast|send\s*\(|recv\s*\(|receive\s*\(|"
    r"\bopen\s*\(|\.open\(|comm->send|comm->recv|network->send|network->recv|"
    r"sendAsync|receiveAsync|recvAsync|send_async|recv_async|"
    r"\.send\(|\.recv\(|\.receive\(|socket\.|net\.Conn|Write\(|Read\(",
)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
    text = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
    text = re.sub(r"(?m)#[^\n]*", lambda m: " " * len(m.group(0)), text)
    return text


def find_functions(text: str):
    out = []
    for m in re.finditer(
        r"(?m)^[\t ]*(?:[\w:<>,~*&\[\]\s]+?)\b(\w+)\s*\([^;{}]*\)\s*(?:const\s*)?(?:->[^{}]+)?\{",
        text,
    ):
        name = m.group(1)
        brace = text.find("{", m.start())
        depth, i = 0, brace
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((name, brace, i + 1, text[brace : i + 1]))
    return out


def field_provenance(text: str):
    """Map field -> 'pool' | 'local' based on assignments anywhere in the file."""
    prov = {}
    for m in re.finditer(r"(?:this\.|self\.)?(\w+)\s*=\s*([^;\n]{0,120})", text):
        field, rhs = m.group(1), m.group(2)
        if re.search(r"getRandomGenerator|jointSeed|joint_seed|drbgGenerator|apply\(seed|AesCtrDrbg", rhs):
            prov.setdefault(field, "pool-public")
        elif re.search(r"get_random|randomizer|SharedRandom|shared_randomness|randomness", rhs):
            prov.setdefault(field, "pool-shared")
        elif re.search(r"new\s+AesCtrDrbg|AesCtrDrbg\(|fromDerivedSeed|SecureRandom", rhs):
            prov.setdefault(field, "local")
    return prov


def collect(body, graph, depth=2, seen=None):
    if seen is None:
        seen = set()
    parts = [body]
    if depth <= 0:
        return "\n".join(parts)
    for call in set(re.findall(r"\b(\w+)\s*\(", body)):
        if call in seen:
            continue
        seen.add(call)
        for callee in graph.get(call, [])[:2]:
            parts.append(collect(callee, graph, depth - 1, seen))
    return "\n".join(parts)


def classify(body, graph, prov):
    local = [rx.search(body) for rx, kind in RANDOM if kind in ("local-drbg", "local-rng", "local-prp") for rx in [rx]]
    direct = [(kind, rx.search(body)) for rx, kind in RANDOM]
    direct = [(k, m) for k, m in direct if m]
    text = collect(body, graph, 2)
    via_callee = [(kind, None) for rx, kind in RANDOM if rx.search(text) and not rx.search(body)]

    if not direct and not via_callee:
        if HASH.search(body):
            return "hash-based", "hash/commitment comparison, no coefficients"
        return "different-mechanism", "no randomness found"

    kinds = {k for k, _ in direct} | {k for k, _ in via_callee}
    first = min((m.start() for _, m in direct), default=None)
    msg = MESSAGE.search(body)

    # 字段溯源：body 引用了来源字段
    for field, src in prov.items():
        if not re.search(rf"\b{re.escape(field)}\b", body):
            continue
        if src == "pool-public":
            return "pre-existing", f"field '{field}' seeded from public pool/DRBG"
        if src == "pool-shared":
            return "post-message", f"field '{field}' from shared-randomness pool"

    if "prss" in kinds:
        return "post-message", "PRSS (secret-shared randomness)"
    if "local-drbg" in kinds or "local-rng" in kinds or "local-prp" in kinds:
        if first is not None and msg and first < msg.start():
            return "pre-message", "local generator created before first message"
        return "post-message", "fresh local generator"
    if "coin-toss" in kinds:
        if first is not None and msg and first < msg.start():
            return "pre-message", "coin tossed before first message"
        return "post-message", "coin tossed inside check"
    if "shared-getter" in kinds:
        return "post-message", "shared-randomness pool (secret)"
    if "pool-getter" in kinds or "drbg-field" in kinds:
        return "pre-existing", "randomness from public pool/field generator"
    return "unknown", ",".join(sorted(kinds))


def scan(repo: Path):
    rows = []
    for path in repo.rglob("*"):
        if path.suffix not in EXTS or not path.is_file():
            continue
        if any(p in {"target", "build", ".git", "node_modules", "deps", "third_party"} for p in path.parts):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = strip_comments(raw.lstrip("\ufeff"))
        funcs = find_functions(text)
        graph = {}
        for name, _, _, body in funcs:
            graph.setdefault(name, []).append(body)
        prov = field_provenance(text)
        for name, start, _, body in funcs:
            if not CHECK_NAME.search(name):
                continue
            order, why = classify(body, graph, prov)
            rows.append({
                "file": str(path.relative_to(repo)),
                "line": text[:start].count("\n") + 1,
                "function": name,
                "order": order,
                "evidence": why,
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out", default="ordertool-out")
    args = ap.parse_args()
    repo = Path(args.repo)
    rows = scan(repo)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "report.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "line", "function", "order", "evidence"])
        w.writeheader()
        w.writerows(rows)

    rank = {"pre-existing": 0, "pre-message": 1, "unknown": 2, "post-message": 3,
            "hash-based": 4, "different-mechanism": 5}
    rows.sort(key=lambda r: (rank.get(r["order"], 9), r["file"]))
    with (out / "report.md").open("w", encoding="utf-8") as f:
        f.write(f"# OrderTool report: {repo}\n\n{len(rows)} check-like functions.\n\n")
        for r in rows:
            if rank.get(r["order"], 9) <= 2:
                f.write(f"- **{r['order']}** `{r['file']}:{r['line']}` `{r['function']}` — {r['evidence']}\n")
    print(f"{len(rows)} checks -> {out/'report.md'}")


if __name__ == "__main__":
    main()
