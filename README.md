# Challenge Binding in FRESCO SPDZ2k: research artifact

Materials for the prepared manuscript *Challenge Binding in FRESCO SPDZ2k: A Message-Level Case Study*. No ePrint paper identifier has been assigned in this package. The manuscript declares predominantly AI-generated work under human direction; the human author remains responsible for its claims, evidence, citations, and code.

The case study examines FRESCO `f8383e6aead6b44d44b798553aaf0bcaccd81dab`. It instantiates a previously published predictable-coefficient cancellation template in the SPDZ2k public-seed path and retains message-level executions with incorrect openings. [FRESCO issue #324](https://github.com/aicis/fresco/issues/324) records the per-check coin-tossing requirement; *[Rushing at SPDZ](https://eprint.iacr.org/2025/789)* supplies the closest earlier attack template.

## Start here

- Manuscript/PDF: [`05-challenge-binding/paper/`](05-challenge-binding/paper/), containing `FRESCO-SPDZ2K-CASE-STUDY-v1.0.md` and `Challenge-Binding-FRESCO-SPDZ2k.pdf`.
- Core reproduction: [`05-challenge-binding/REPRODUCING.md`](05-challenge-binding/REPRODUCING.md), retaining Appendix B's commands. Start at the repository root, the directory containing `05-challenge-binding/`.
- Dated execution evidence: [`05-challenge-binding/data/verification-2026-11-03/`](05-challenge-binding/data/verification-2026-11-03/), especially `evidence-index.json` and `run-manifest.json`.
- Evidence/path map and the 26-spec replay: [`05-challenge-binding/README.md`](05-challenge-binding/README.md).
- Packaging provenance: [`PACKAGED-FILES.csv`](PACKAGED-FILES.csv) lists the original package-relative source, byte length, and SHA-256 of newly copied inputs. [`SHA256SUMS`](SHA256SUMS) covers released files except itself.

## Layout

The focused `05-challenge-binding/` snapshot contains existing tests, the supplied candidate patch, historical records, 26 annotated transcript specifications, ten selected MPC scan targets, four scan-mutation targets, and dated core verification. Its deliberate `code/artifact/kernel/kernel/` and `code/artifact/synth/synth/` paths preserve the manuscript's layout.

Earlier compact release paths remain available: `code/kernel/`, `code/attack_synth/`, `data/*.zip`, `data/specs/`, `data/*-report.json`, and `tables/kernel-evidence.csv`. Their bytes are preserved. The focused snapshot is the revised manuscript's reference layout; its README maps paths. Read historical tables and README files with the corrections below.

[`source/fresco-f8383e6/`](source/fresco-f8383e6/) retains 29 Java inspection snapshots, eight POMs, original source manifests, and a new relative-path index. These selected files do not form a full buildable FRESCO tree. Appendix B obtains the complete pinned revision separately.

## Recorded outcomes

The dated verification used a fresh checkout, Maven 3.9.9, Temurin OpenJDK 21.0.11+10-LTS, an isolated Maven repository, dummy preprocessing, and party threads within one JVM on Windows 11 amd64. It is author-requested AI-assisted verification, separate from historical counts and not independent laboratory replication.

| Execution | Retained outcome |
|---|---|
| Unchanged message-level class | Five tests, zero failures/errors; honest `[50, 600]`; three normally returned tampered pairs violate `P - 20(S - 20) = 0 mod 2^64` |
| Unchanged eleven-case suite on original upstream | Eleven tests, zero failures/errors, subject to the oracle limitations below |
| Same suite after only the supplied four-file patch | Four baselines complete; seven errors contain `MaliciousException: Mac check failed`; nonzero Maven exit expected |
| Declared transcript specification replay | 26/26 expected verdicts after correcting input/import paths in memory |

The seven patched-suite errors are MAC-rejection evidence for these scenarios, **not a passing patched regression suite**. Compilation, dependency, or unrelated exceptions do not demonstrate rejection. The patch remains a candidate mitigation; malicious-state, coin-tossing, replay, synchronization, and ring-valued soundness analyses remain unfinished.

Two legacy oracles limit original pass counts: `attackComputedProducts` compares products against a helper that generates sums, allowing honest products to satisfy its inequality; `attackMultiCheck` has no output-change assertion. Their passes establish normal suite execution, not those output-corruption claims. Dedicated application/message-level records, the functional relation, and the source argument supply the computation-level evidence. The paper also discusses shared static output storage and why normal-return logs are needed alongside exception-catching assertions.

Older sanitized Surefire XML has unescaped angle-bracket path placeholders and is not reliable machine-readable XML. Use readable text reports or separate valid dated XML. Historical K=1 logs may record skipped edits and do not give an edit-acceptance rate. Timing intervals lack retained instrumentation sufficient for deployment-overhead claims.

## Audit context and remaining limits

The transcript monitor checks author-supplied dependency models, not their semantic correctness or overall protocol security. OrderTool produces heuristic source-pattern candidates. The ten selected targets contain 347 records; their purposive selection, labels, and zero-candidate counts support no population or repository-wide security conclusion. The focused snapshot includes those ten and four mutation variants, rather than every exploratory scan.

`synth-report-real.json` supplies a historical three-coefficient parameter vector whose original seed and raw log are not retained. It is an algebraic input example, not another FRESCO execution. MASCOT remains a bounded check-level probe; its non-kernel control catches any `RuntimeException` without asserting exception type. No emp-agmpc protocol-level execution or production-deployment attack is established.

Preserved historical `run_all.py` needs source snapshots and entry points absent here. It is not the current reproduction entry point; no fresh 18/18 full-harness result is claimed. `run_specs.py` and some inspection helpers retain old paths. The focused README documents the 26-spec replay with in-memory path setup and unchanged source/JSON bytes. The broader historical survey has not been restored. Appendix B covers core FRESCO execution.

## Provenance and licenses

Copied code, patch, source snapshots, logs, and reports retain their input bytes. Packaging did not repair implementations or rerun Maven. Dated records contain original local project paths and environment properties; earlier sanitized archives are also unchanged. The original verification index's manuscript hash identifies the recipe version used then and may differ from the subsequently revised publication file.

Existing [`LICENSE`](LICENSE) remains verbatim: text/data are declared CC BY 4.0 and code in `code/` MIT. Its brief declaration lacks standard license texts and a code copyright-holder notice. FRESCO material retains its own copyright/permission notice; see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and [`third_party/FRESCO-LICENSE.md`](third_party/FRESCO-LICENSE.md). No blanket relicensing of third-party material is intended.
