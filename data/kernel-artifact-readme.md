# Kernel-vector and MASCOT evidence

This directory holds the executable evidence for the unified paper's FRESCO case study. It is
split from the specification harness in `../` because it needs a FRESCO checkout; the
specification harness does not.

Pinned upstream revision: `f8383e6aead6b44d44b798553aaf0bcaccd81dab` (FRESCO 1.3.9,
2026-05-20). The tests run against `_hunt/fresco` in the project, or any clone at that
revision.

## Layout

| Path | Content |
|---|---|
| `TestKernelAttack.java`, `TestKernelVariants.java` | deterministic `e = (r_j, -r_i)` tests: K=2 at 2/3/4 parties; K=3/5/8; non-kernel controls; K=1 high-bit-only case |
| `kernel1.log`, `kernel2.log` | early runs; `kernel1.log` is an exploratory box-constrained run that printed `KERNEL_RESULT nosol` and is kept for provenance, not as a kernel result |
| `runs/unpatched/`, `runs/patched/` | the recorded run logs, grouped; aggregate with `python runs/parse_results.py` (writes `runs/SUMMARY.md`) |
| `patched/` | surefire reports from the patched tree; the `TestKernelVariants` report there records K3/K5/K8/K1 as `blocked` — this is the patched-tree run, not the unpatched one |
| `appoutput/TestKernelAppOutput.java`, `appoutput/run.log` | protocol-level probe: a three-party sum/product task; honest `[50, 600]`, tampered outputs accepted |
| `disclosed/TestSpdz2kMacCheckCancellation.java` | the eleven-case suite sent to the maintainers (four honest baselines, seven attack cases; uses the earlier non-negative-box solver) |
| `disclosed/fix.patch` | the four-file candidate patch |
| `disclosed/TEST-*.xml` | surefire report of the suite on the patched tree |
| `mascot/TestMascotInputGap.java` | element-generation probe: shares `v + e`, MACs for `v`; kernel and non-kernel control |
| `mascot/install_hook.py` | installs the test-only transform hook for the element-generation probe |
| `mascot/TestSpdzMascotPropagation.java` | two-party SPDZ with MASCOT preprocessing; corrupted input-mask batch |
| `mascot/install_hook_oneshot.py` | installs the one-shot transform hook for the propagation probe |
| `mascot/run-input-gap.log` | output: `MASCOT_GAP accepted; opened=[6383, 19794]` |
| `mascot/run-spdz.log` | output: `SPDZ_PROP aborted=true cause=MaliciousException ...` |
| `timing/TestSpdz2kMacCheckOverhead.java` | author-run JUnit test-time A/B class (n=5 per configuration) |
| `timing/ov-base-*.log`, `timing/ov-fix-*.log`, `timing/ov8-*.log` | A/B test wall-clock logs |
| `timing/summarize_existing_timings.py` | reduces the `seed_ns`/`check_ns` timing logs |
| `timing/timing-summary.json` | the reduced medians |

## Run groups

`runs/parse_results.py` scans `runs/unpatched` and `runs/patched` for `*_RESULT` lines and
writes `runs/SUMMARY.md`. The groups are:

| Group | Configuration |
|---|---|
| `ku-*.log` | 30 unpatched K=2 three-party kernel runs |
| `k2p-*.log` | unpatched K=2 two-party runs |
| `k4p.log` | unpatched K=2 four-party run |
| `k35.log` | unpatched K=3 and K=5 variants |
| `kv-*.log`, `kv3-*.log` | further variant configurations (K=1/K=8) |
| `ctrl*.log` | non-kernel controls |
| `kf-*.log` | patched K=2 runs |
| `fk8-*.log` | patched K=1/K=8 runs |
| `pk1-*.log` | patched K=1 runs |

The logs are UTF-8. `runs/SUMMARY.md` reports raw counts per group; the paper's Table 4
reports the canonical subset and the artifact ships the exploratory runs as well.

## Canonical mapping (Table 4 row -> logs)

| Table 4 row | Canonical logs |
|---|---|
| K=2, three parties, 30 | `runs/unpatched/ku-0.log` .. `ku-29.log` |
| K=2, two parties, 4 | `runs/unpatched/k2p.log`, `k2p-0.log` .. `k2p-2.log` |
| K=2, four parties, 1 | `runs/unpatched/k4p.log` |
| K=3 / K=5, 1 / 1 | `runs/unpatched/k35.log` |
| K=8, 6 | `runs/unpatched/kv-0.log` .. `kv-5.log` |
| controls, 3 configurations | `runs/unpatched/ctrl1.log` .. `ctrl3.log` |
| patched K=2, 6 | `runs/patched/kf-0.log` .. `kf-5.log` |
| patched K=3 / K=5, 1 / 1 | `runs/patched/kpk35.log` |
| patched K=8, 6 | `runs/patched/fk8-0.log` .. `fk8-5.log` |
| K=1 unpatched 6 / patched 8 | `runs/unpatched/kv3-*.log`, `runs/patched/pk1-*.log` |
| disclosed eleven-case suite, 13 runs | `disclosed/runs/fresco-final1..5.log`, `disclosed/runs/stab-0..7.log` |

## Commands

Run from the FRESCO checkout root. The kernel tests go into the SPDZ2k test package:

```bash
cp TestKernelAttack.java TestKernelVariants.java \
   suite/spdz2k/src/test/java/dk/alexandra/fresco/suite/spdz2k/protocols/computations/
mvn -pl suite/spdz2k -Dtest=TestKernelAttack,TestKernelVariants test
```

Expect the `K*_RESULT` lines in the console; the unpatched classes accept the kernel vectors
and block the non-kernel controls. The recorded repeat runs were made by invoking the same
command and appending its output to `ku-$i.log`; `runs/parse_results.py` aggregates them.

MASCOT element-generation probe (installs a test-only hook, then removes it):

```bash
python install_hook.py
cp TestMascotInputGap.java tools/mascot/src/test/java/dk/alexandra/fresco/tools/mascot/elgen/
mvn -pl tools/mascot -Dtest=TestMascotInputGap test
git checkout -- tools/mascot/src/main/java/dk/alexandra/fresco/tools/mascot/elgen/ElementGeneration.java
```

Expected: honest run opens `[11, 22]`; malicious run prints
`MASCOT_GAP accepted; opened=[6383, 19794]`; the non-kernel control is rejected.

SPDZ + MASCOT propagation probe:

```bash
python mascot/install_hook_oneshot.py
cp mascot/TestSpdzMascotPropagation.java suite/spdz/src/test/java/dk/alexandra/fresco/suite/spdz/
mvn -pl suite/spdz -Dtest=TestSpdzMascotPropagation test
git checkout -- tools/mascot/src/main/java/dk/alexandra/fresco/tools/mascot/elgen/ElementGeneration.java
```

Expected: `SPDZ_PROP honest opened=[5]` and `SPDZ_PROP aborted=true` with
`MaliciousException: The sum of delta's was not 0 ...`.

Disclosed eleven-case suite:

```bash
cp disclosed/TestSpdz2kMacCheckCancellation.java \
   suite/spdz2k/src/test/java/dk/alexandra/fresco/suite/spdz2k/protocols/computations/
mvn -pl suite/spdz2k -Dtest=TestSpdz2kMacCheckCancellation test   # 11 pass
git apply disclosed/fix.patch
mvn -pl suite/spdz2k -Dtest=TestSpdz2kMacCheckCancellation test   # 4 pass, 7 errors
```

## Limits

- Author-run, one machine and one JVM, dummy preprocessing; the artifact lets a reader repeat
  the runs, it is not independent replication.
- The MASCOT hooks are test-only edits to `ElementGeneration`; they are reverted after each
  run and are not part of the code studied.
- The MASCOT probe uses two parties and field modulus 65519; the SPDZ propagation probe tests
  the input-mask path only. Other consumption paths (triples, random bits, masks not opened)
  are not covered.
- The disclosed suite implements the earlier non-negative-box solver, not the kernel vector;
  the kernel vector is evidenced by the two test classes in this directory.
- Timing numbers are single-machine medians; the 20–31% figure is a share of the check time,
  and the A/B numbers are JUnit test wall-clock times, not application-level benchmarks.
