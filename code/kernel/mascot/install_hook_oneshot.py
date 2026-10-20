#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Install the one-shot MASCOT input transform hook.

Applies a test-only transform to the shares of one party, once, then clears itself.
Revert with `git checkout -- tools/mascot/src/main/java/.../elgen/ElementGeneration.java`.
"""

from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[3]
P = (Path(os.environ.get("FRESCO_ROOT", "fresco")) / "tools/mascot/src/main/java"
         r"\dk\alexandra\fresco\tools\mascot\elgen\ElementGeneration.java")

t = P.read_text(encoding="utf-8")
marker = "public class ElementGeneration {\n"
hook = (marker + "\n  /** Test-only hook: one-shot transform of the shares, for a chosen party. */\n"
        "  public static volatile java.util.function.UnaryOperator<java.util.List<FieldElement>> maliciousShareTransform = null;\n"
        "  public static volatile Integer maliciousPartyId = null;\n")
if "maliciousShareTransform" not in t:
    assert marker in t
    t = t.replace(marker, hook, 1)

old = "    List<FieldElement> shares = secretShare(values, resourcePool.getNoOfParties());"
new = ("    List<FieldElement> shareValues = values;\n"
       "    if (maliciousShareTransform != null\n"
       "        && (maliciousPartyId == null || maliciousPartyId == resourcePool.getMyId())) {\n"
       "      shareValues = maliciousShareTransform.apply(values);\n"
       "      maliciousShareTransform = null;\n"
       "    }\n"
       "    List<FieldElement> shares = secretShare(shareValues, resourcePool.getNoOfParties());")
assert old in t
t = t.replace(old, new, 1)
P.write_text(t, encoding="utf-8")
print("one-shot hook installed")
