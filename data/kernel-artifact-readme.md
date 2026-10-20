# Kernel-vector and MASCOT evidence (released bundles)

This file is the row-to-log map for the FRESCO case study. In the released package the evidence is
under `code/kernel/` (tests, patch, MASCOT probes) and `data/` (recorded logs and reports); the
workspace names are given in parentheses where useful.

Pinned upstream revision: `f8383e6aead6b44d44b798553aaf0bcaccd81dab` (FRESCO 1.3.9,
2026-05-20).

## Where the evidence is

| Released path | Content |
|---|---|
| `code/kernel/TestKernelAttack.java`, `code/kernel/TestKernelVariants.java` | deterministic `e = (r_j, -r_i)` tests: K=2 at 2/3/4 parties; K=3/5/8; non-kernel controls; K=1 high-bit case |
| `code/kernel/TestKernelAppOutput.java` | protocol-level three-party sum/product probe |
| `data/appoutput.zip` (`appoutput/`) | its run log: honest `[50, 600]`; tampered `[4143675807337242761, 9821738699198359411]` accepted |
| `code/kernel/TestKernelMessageLevel.java`, `data/message-level.zip` | message-level reachability: a corrupt party's own opening protocol sends shifted shares; unmodified honest parties accept wrong outputs; includes run log and surefire report |
| `data/kernel-runs.zip` (`kernel-runs/unpatched/`, `kernel-runs/patched/`) | recorded kernel-vector run logs |
| `code/kernel/parse_results.py` | aggregator for the run logs (fixes `KERNEL2P_RESULT`/`KERNEL4P_RESULT` rows) |
| `data/kernel-runs-summary.md` | aggregator output |
| `code/kernel/TestSpdz2kMacCheckCancellation.java`, `code/kernel/fix.patch` | eleven-case suite and four-file candidate patch |
| `data/disclosed-runs.zip` (`disclosed-runs/`) | thirteen suite runs (`fresco-final1..5`, `stab-0..7`) |
| `code/kernel/mascot/` | MASCOT element-generation and SPDZ propagation probes, hook installers |
| `data/timing.zip` (`timing/`) | raw author-run timing logs (no percentages are reported in the paper) |
| `data/corpus-mutation/` | mutation-study reports (`mutation-mpspdz`, `mutation-coral`, `mutation-scale`, `mutation-spdz`) |

Logs and surefire reports were sanitized before release: local project paths are replaced by
`<PROJECT>`, the user profile by `<USER>`, Maven cache paths by `<M2>`, and the JDK path by
`<JAVA_HOME>`.

## Run groups and totals

`code/kernel/parse_results.py` scans `kernel-runs/unpatched` and `kernel-runs/patched` in
`data/kernel-runs.zip` for `*_RESULT` lines and regenerates `data/kernel-runs-summary.md`. The
paper table is the **designated canonical subset**; the bundles also ship exploratory repeats.
Full result-line totals include:

- three-party K=2 successes: 35 (`ku-0..29`, four in `k2p*`, one in `k4p`);
- two-party successes: 5 (four in `k2p*`, one in `k4p`);
- four-party success: 1 (`k4p`);
- K=8 changed: 6 unpatched (`kv-0..5`) and 6 patched (`fk8-0..5`);
- K=1 unpatched: 14 `unchanged` (4 in `kv*`, 6 in `kv3*`, 3 in `ctrl*`, 1 in `k*`) and 2
  `error` (`kv-1`, `kv-5`); K=1 patched: 11 `unchanged` and 3 `blocked`;
- non-kernel controls: 3 configurations blocked.

The K=1 test applies an edit only for even coefficients; for odd coefficients it skips the edit
and still prints `unchanged`. The logs do not record applicability, so the paper reports the K=1
row as a bounded observation, not an edit-acceptance count. The two `K1_RESULT error` lines are
retained and not investigated.

## Canonical mapping (paper table row -> logs)

| Paper row | Canonical logs (inside `data/kernel-runs.zip`) |
|---|---|
| K=2, three parties, 30 | `kernel-runs/unpatched/ku-0.log` .. `ku-29.log` |
| K=2, two parties, 4 | `kernel-runs/unpatched/k2p.log`, `k2p-0.log` .. `k2p-2.log` |
| K=2, four parties, 1 | `kernel-runs/unpatched/k4p.log` |
| K=3 / K=5, 1 / 1 | `kernel-runs/unpatched/k35.log` |
| K=8, 6 | `kernel-runs/unpatched/kv-0.log` .. `kv-5.log` |
| controls, 3 configurations | `kernel-runs/unpatched/ctrl1.log` .. `ctrl3.log` |
| patched K=2, 6 | `kernel-runs/patched/kf-0.log` .. `kf-5.log` |
| patched K=3 / K=5, 1 / 1 | `kernel-runs/patched/kpk35.log` |
| patched K=8, 6 | `kernel-runs/patched/fk8-0.log` .. `fk8-5.log` |
| K=1 unpatched 6 / patched 8 | `kernel-runs/unpatched/kv3-*.log`, `kernel-runs/patched/pk1-*.log` |
| disclosed eleven-case suite, 13 runs | `disclosed-runs/fresco-final1..5.log`, `disclosed-runs/stab-0..7.log` |

## Commands

Run from a FRESCO checkout at `f8383e6`. The kernel tests go into the SPDZ2k test package:

```bash
cp code/kernel/TestKernelAttack.java code/kernel/TestKernelVariants.java \
   suite/spdz2k/src/test/java/dk/alexandra/fresco/suite/spdz2k/protocols/computations/
mvn -pl suite/spdz2k -Dtest=TestKernelAttack,TestKernelVariants test
```

Expect `K*_RESULT` lines; the unpatched classes accept the kernel vectors and block the non-kernel
controls. To regenerate the summary, unzip `data/kernel-runs.zip` and run
`python code/kernel/parse_results.py` with `kernel-runs/` as the working directory.

MASCOT element-generation probe:

```bash
python code/kernel/mascot/install_hook.py
cp code/kernel/mascot/TestMascotInputGap.java tools/mascot/src/test/java/dk/alexandra/fresco/tools/mascot/elgen/
mvn -pl tools/mascot -Dtest=TestMascotInputGap test
git checkout -- tools/mascot/src/main/java/dk/alexandra/fresco/tools/mascot/elgen/ElementGeneration.java
```

Expected: honest run opens `[11, 22]`; malicious run prints
`MASCOT_GAP accepted; opened=[6383, 19794]`; the non-kernel control is rejected.

SPDZ + MASCOT propagation probe:

```bash
python code/kernel/mascot/install_hook_oneshot.py
cp code/kernel/mascot/TestSpdzMascotPropagation.java suite/spdz/src/test/java/dk/alexandra/fresco/suite/spdz/
mvn -pl suite/spdz -Dtest=TestSpdzMascotPropagation test
git checkout -- tools/mascot/src/main/java/dk/alexandra/fresco/tools/mascot/elgen/ElementGeneration.java
```

Expected: `SPDZ_PROP honest opened=[5]` and `SPDZ_PROP aborted=true` with
`MaliciousException: The sum of delta's was not 0 ...`.

Disclosed eleven-case suite:

```bash
cp code/kernel/TestSpdz2kMacCheckCancellation.java \
   suite/spdz2k/src/test/java/dk/alexandra/fresco/suite/spdz2k/protocols/computations/
mvn -pl suite/spdz2k -Dtest=TestSpdz2kMacCheckCancellation test   # 11 pass
git apply code/kernel/fix.patch
mvn -pl suite/spdz2k -Dtest=TestSpdz2kMacCheckCancellation test   # 4 pass, 7 errors
```

## Message-level reachability

`TestKernelMessageLevel` is the model-free counterpart of the object-level `TestKernelAppOutput`
probe. The corrupt party's application appends its own opening protocol; it sends the
least-significant share of an authenticated element whose share has been shifted by the kernel
vector and keeps the MAC share. Honest parties run FRESCO's original `Spdz2kOutputToAllProtocol`.
The recorded run (`data/message-level.zip`, `run.log`) has honest `[50, 600]`, an accepted
tampered run with wrong outputs, and a blocked non-kernel control.

## Limits

- Author-run, one machine and one JVM, dummy preprocessing; the artifact lets a reader repeat the
  runs, it is not independent replication.
- The MASCOT hooks are test-only edits to `ElementGeneration`; they are reverted after each run
  and are not part of the code studied.
- The MASCOT probe uses two parties and field modulus 65519; the SPDZ propagation probe tests the
  input-mask path only. Other consumption paths (triples, random bits, masks not opened) are not
  covered.
- The disclosed suite implements the earlier non-negative-box solver, not the kernel vector; the
  kernel vector is evidenced by the two kernel test classes.
- The K=1 high-bit test skips the edit when the coefficient is odd; applicability was not logged.
- Timing logs are shipped for completeness only. Because the instrumentation is not retained with
  the measured revision, no percentage or deployment-overhead claim is made.
- In `appoutput/run.log`, `APPOUT_TAMPER_RESULT status=1` is a tamper flag set by the test,
  not an error or process exit code.
- The MASCOT non-kernel control catches `RuntimeException` and sets `rejected=true`; the
  exception type is not asserted, so it shows "the control aborted", not that the MAC check
  rejected it.
- `binding.py` reports the single-value case as bound; `binding-report.json` records only the
  two-value attackable case.
