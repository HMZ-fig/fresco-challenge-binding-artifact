#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Close the synthesis -> execute -> confirm loop against a FRESCO checkout.

Steps: emit the JUnit test (emit_junit.py), copy it into the SPDZ2k test package, run it with
Maven, parse the SYNTH_* markers, write a report, and remove the generated file unless
--keep is given.

Usage:
    python verify.py --fresco-root <PROJECT>/_hunt/fresco --batch 4
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parents[1]
DEFAULT_MVN = ROOT / "_hunt" / "apache-maven-3.9.9" / "bin" / "mvn.cmd"
DEFAULT_SETTINGS = ROOT / "_hunt" / "maven-settings.xml"
PACKAGE = "suite/spdz2k/src/test/java/dk/alexandra/fresco/suite/spdz2k/protocols/computations"


def parse_markers(text: str) -> dict:
    out: dict = {}
    m = re.search(r"SYNTH_HONEST_RESULT status=(\d+) opened=\[([^\]]*)\]", text)
    if m:
        out["honest"] = {"status": int(m.group(1)),
                         "opened": [int(x) for x in m.group(2).split(",") if x.strip()]}
    m = re.search(r"SYNTH_TAMPER_RESULT status=(\d+) opened=\[([^\]]*)\]", text)
    if m:
        out["tamper"] = {"status": int(m.group(1)),
                         "opened": [int(x) for x in m.group(2).split(",") if x.strip()]}
    if "SYNTH_TAMPER_RESULT blocked" in text:
        out["tamper_blocked"] = True
    out["honest_ok"] = "SYNTH_HONEST_OK true" in text
    out["tamper_ok"] = "SYNTH_TAMPER_OK true" in text
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fresco-root", type=Path, default=ROOT / "_hunt" / "fresco")
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--class-name", default="SynthAppOutputTest")
    ap.add_argument("--mvn", type=Path, default=DEFAULT_MVN)
    ap.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS)
    ap.add_argument("--json", type=Path, default=ROOT / "artifact" / "synth" / "verify-report.json")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    pkg_dir = args.fresco_root / PACKAGE
    if not pkg_dir.exists():
        print(f"missing package dir: {pkg_dir}", file=sys.stderr)
        return 2
    target = pkg_dir / f"{args.class_name}.java"

    sys.path.insert(0, str(TOOLS))
    from emit_junit import emit  # noqa: E402

    emit(pkg_dir, args.batch, args.class_name)
    cmd = [str(args.mvn), "-B", "-s", str(args.settings), "-pl", "suite/spdz2k",
           f"-Dtest={args.class_name}", "test"]
    env = dict(os.environ)
    env.setdefault("JAVA_HOME", r"<JAVA_HOME>")
    try:
        proc = subprocess.run(cmd, cwd=str(args.fresco_root), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env)
    finally:
        if not args.keep:
            target.unlink(missing_ok=True)

    log = proc.stdout + "\n" + proc.stderr
    result = parse_markers(log)
    result["maven_exit"] = proc.returncode
    result["batch"] = args.batch
    result["class"] = args.class_name
    result["log_tail"] = log.strip().splitlines()[-15:]
    ok = bool(result.get("honest_ok") and result.get("tamper_ok"))
    result["confirmed"] = ok
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("honest", "tamper", "honest_ok", "tamper_ok",
                                             "confirmed", "maven_exit")}, indent=2))
    print(f"wrote {args.json}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
