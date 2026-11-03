# Focused manuscript snapshot

Evidence paths in the revised FRESCO manuscript are relative to this directory. For the core PowerShell recipe in [REPRODUCING.md](REPRODUCING.md), start at the repository root (this directory's parent), which contains `05-challenge-binding/`. The recipe needs a separate full pinned upstream checkout and Maven/Java dependencies. Core executions are already recorded under `data/verification-2026-11-03/`. The 26-spec replay below instead starts in this directory.

## Evidence locations

| Path here | Contents / earlier root-level counterpart |
|---|---|
| `code/artifact/kernel/kernel/TestKernelAttack.java`, `TestKernelVariants.java` | Kernel tests; `../code/kernel/` |
| `code/artifact/kernel/kernel/appoutput/` | Sum/product source and historical record; `../code/kernel/TestKernelAppOutput.java`, `../data/appoutput.zip` |
| `code/artifact/kernel/kernel/messagelevel/` | Message-level source and historical records; `../code/kernel/TestKernelMessageLevel.java`, `../data/message-level.zip` |
| `code/artifact/kernel/kernel/disclosed/` | Eleven-case source, candidate patch, readable patched report, old runs; `../code/kernel/TestSpdz2kMacCheckCancellation.java`, `../code/kernel/fix.patch`, `../data/disclosed-runs.zip`, `../data/patched-regression.zip` |
| `code/artifact/kernel/kernel/runs/` | Kernel logs and K=1 applicability control; `../data/kernel-runs.zip` plus the separately retained applicability log |
| `code/artifact/kernel/kernel/mascot/` | Probe sources and logs; `../code/kernel/mascot/`, `../data/mascot.zip` |
| `code/artifact/kernel/kernel/timing/` | Timing records and existing helper/test source; `../data/timing.zip`, `../data/timing-summary.json` |
| `code/artifact/synth/synth/`, `data/synth/` | Synthesis/audit/binding/emitter/driver and reports; `../code/attack_synth/`, `../data/*-report.json` |
| `data/specs/` | All 26 annotated specifications; also `../data/specs/` |
| `code/tool/transcript_monitor/transcript_monitor/` | Original monitor and mutation sources |
| `code/tool/specgen/specgen/` | Original extraction/consistency sources; some need missing survey inputs and old absolute paths |
| `code/tool/ordertool/ordertool.py`, `data/ordertool/out/` | Original scanner, ten selected targets, four mutation variants |
| `data/verification-2026-11-03/` | Dated core execution, separate from historical counts |
| `../source/fresco-f8383e6/` | Upstream inspection snapshots and manifests |

The retained historical kernel README uses older compact root paths. This table and the root README give the current map, oracle corrections, evidence scope, and licenses. Historical source/report bytes have not been edited to rewrite their paths or claims.

## Replay the declared 26-spec verdicts

Run this from this directory in PowerShell. It imports the original script using the correct module path and changes the specification input path only in memory. Source/JSON bytes remain unchanged. This is separate from FRESCO execution.

```powershell
@'
from pathlib import Path
import importlib.util
import sys
package = Path.cwd()
sys.path.insert(0, str(package / "code/tool/transcript_monitor/transcript_monitor"))
loader = importlib.util.spec_from_file_location("artifact_specs", package / "code/artifact/run_specs.py")
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)
module.SPECS = package / "data/specs"
module.main()
'@ | python -B -
```

Expected final line: `26/26 specs match expectation`. Historical `run_all.py` is retained for inspection; it needs absent survey inputs. The 14-source-pattern checker also needs unshipped snapshots. Neither is represented as currently passing here.

## Selected source-scan targets

`mpspdz` (139), `scale-mamba` (63), `opencoral` (42), `mpc4j-abb3` (30), `motion` (25), `libscapi` (19), `fresco-spdz2k` (10), `ark-mpc` (10), `emp-agmpc` (7), `spu-swift` (2): 347 records. Mutation directories: `mutation-mpspdz`, `mutation-coral`, `mutation-scale`, `mutation-spdz`. Both `.csv` and `.md` files are verbatim copies. Local source-root paths in headings record provenance and may not resolve elsewhere.

The dated index records five message tests without errors, eleven original disclosed tests without errors, and seven patched MAC-rejection errors with four completed baselines. Its run manifest records inputs, residues, commands, and fingerprints. The seven errors are rejection evidence, not a fully passing patched regression suite. See the root README and manuscript for both legacy oracle limitations.
