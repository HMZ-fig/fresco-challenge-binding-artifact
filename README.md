# Challenge Binding in Cryptographic Implementations: artifact

Artifact for the manuscript *Challenge Binding in Cryptographic Implementations: Transcript
Coverage and Randomness Ordering* (IACR Cryptology ePrint Archive). This repository contains only
the frozen code, recorded data and result tables.

## Contents

- `code/attack_synth/`: kernel-vector synthesis (`synth.py`), missing-binding decision
  (`binding.py`), coefficient-source audit (`audit.py`), JUnit emitter (`emit_junit.py`) and
  execution driver (`verify.py`).
- `code/kernel/`: FRESCO SPDZ2k test classes (kernel vector, protocol-level sum/product), the
  disclosed eleven-case suite and its four-file patch, and the MASCOT probe hooks.
- `data/`: recorded reports. `synth-report-real.json` and `synth-report-k4.json` show
  residual 0 with both low parts changed; `binding-report.json` reproduces the probe deltas
  `[6372, 19772]`; `verify-report.json` records honest `[50, 600]` and an accepted tampered
  run.
- `tables/kernel-evidence.csv`: the configuration-by-configuration evidence table.

## Provenance

The tests run against FRESCO at commit `f8383e6` (1.3.9). Commands and expected outputs are in
`code/attack_synth/README.md` and `data/kernel-artifact-readme.md`. Experiments were author-run
on one machine and one JVM with dummy preprocessing; the artifact lets a reader repeat them and is
not independent replication.

## License

Text and data: CC BY 4.0. Code: MIT. See `LICENSE`.
