# Challenge Binding in FRESCO SPDZ2k: artifact

Artifact for the manuscript *Challenge Binding in FRESCO SPDZ2k: A Message-Level Case Study* (IACR Cryptology ePrint Archive). This
repository contains only the frozen code, recorded data and result tables.

## Contents

- `code/attack_synth/`: kernel-vector synthesis (`synth.py`), missing-binding decision
  (`binding.py`), coefficient-source audit (`audit.py`), JUnit emitter (`emit_junit.py`) and
  execution driver (`verify.py`).
- `code/kernel/`: FRESCO SPDZ2k test classes (kernel vector, protocol-level sum/product,
  message-level opening), the
  disclosed eleven-case suite and its four-file patch, and the MASCOT probe hooks.
- `data/`: recorded reports and evidence bundles. `synth-report-real.json` and
  `synth-report-k4.json` show residual 0 with both low parts changed; `binding-report.json`
  reproduces the probe deltas `[6372, 19772]`; `verify-report.json` records honest `[50, 600]`
  and an accepted tampered run; `audit-report.json` classifies 17 checks in eight frameworks.
  Bundles: `kernel-runs.zip` (canonical kernel-vector runs), `disclosed-runs.zip` (eleven-case
  suite runs), `appoutput.zip` (protocol-level sum/product probe, including the run log with
  `[4143675807337242761, 9821738699198359411]`) and `timing.zip` (raw timing logs). The
  `corpus-mutation/` holds the mutation-study reports; the row-to-log mapping is in
  `data/kernel-artifact-readme.md`. In `appoutput.zip`, `APPOUT_TAMPER_RESULT status=1` is a
  tamper flag set by the test, not an error code.
- `tables/kernel-evidence.csv`: the configuration-by-configuration evidence table.

## Provenance

The tests run against FRESCO at commit `f8383e6` (1.3.9). Commands and expected outputs are in
`code/attack_synth/README.md` and `data/kernel-artifact-readme.md`.

The design rule is public: FRESCO issue #324 (2018-12-10, still open) records that SPDZ2k and
MASCOT must toss fresh coins for every MAC check and marks both as not fixed. This artifact
does not claim discovery of the rule; it ships an executable instantiation, the protocol-level
run, the single-opening boundary, a four-file candidate patch and reproducible logs.

Experiments were author-run on one machine and one JVM with dummy preprocessing; the artifact
lets a reader repeat them and is not independent replication.

The MASCOT non-kernel control catches any `RuntimeException`; the exception type is not asserted.
`binding.py` reports the single-value case as bound, while `binding-report.json` records only the
two-value attackable case.

## License

Text and data: CC BY 4.0. Code: MIT. See `LICENSE`.
