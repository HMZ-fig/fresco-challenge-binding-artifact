#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Install the MASCOT input gap test hook.

Run from anywhere with the FRESCO tree at _hunt/fresco; revert with
`git checkout -- tools/mascot/src/main/java/.../elgen/ElementGeneration.java`.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
P = (ROOT / "_hunt/fresco/tools/mascot/src/main/java"
         r"\dk\alexandra\fresco\tools\mascot\elgen\ElementGeneration.java")

t = P.read_text(encoding="utf-8")

marker = "public class ElementGeneration {\n"
hook = (marker + "\n  /** Test-only hook: when non-null, the inputter shares these values instead of the input. */\n"
        "  public static volatile java.util.List<dk.alexandra.fresco.framework.builder.numeric.field.FieldElement> maliciousShareValues = null;\n")
if "maliciousShareValues" not in t:
    assert marker in t
    t = t.replace(marker, hook, 1)

old = "    List<FieldElement> shares = secretShare(values, resourcePool.getNoOfParties());"
new = ("    List<FieldElement> shareValues = maliciousShareValues != null ? maliciousShareValues : values;\n"
       "    List<FieldElement> shares = secretShare(shareValues, resourcePool.getNoOfParties());")
assert old in t
t = t.replace(old, new, 1)
P.write_text(t, encoding="utf-8")
print("hook installed")
