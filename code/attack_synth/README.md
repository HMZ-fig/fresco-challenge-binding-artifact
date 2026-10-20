# Automated kernel-vector synthesis and source audit

Two small tools behind the paper's "automated synthesis" claim. They take the manual part of
the FRESCO case study and make it reproducible from parameters.

## `synth.py` — kernel-vector synthesis

Model: a batched consistency check over `Z_{2^m}` with coefficients `r_1..r_K` known before
the adversary chooses its errors, and a corrupt party that can tamper with a chosen set of
opened values. The check accepts iff `sum_i r_i e_i == 0 (mod 2^m)`. The tool solves that
linear congruence for a tampering vector `e`, then verifies the residual is zero and that at
least two opened low parts change (`e_i mod 2^k != 0`).

```bash
# from a recorded run (parses the coeffs=[...] line)
python synth.py --log run.log --k 64 --positions last

# from explicit coefficients (synthetic K=4)
python synth.py --coeffs 123,456,789,1011 --m 128 --k 64 --positions 2,3
```

Output: JSON with coefficients, positions, kernel vector, residual, low-part deltas, whether
the check accepts, whether the output changes, and the kernel multiplicity. Exit code 0 iff
both acceptance and output change are established.

Validated results (shipped):

| Input | Result |
|---|---|
| recorded FRESCO coefficient stream (`artifact/synth-report-real.json`) | K=3, positions last two, residual 0, both low parts change |
| synthetic K=4 (`artifact/synth-report-k4.json`) | positions 2,3, residual 0, both low parts change |

## `audit.py` — coefficient-source audit

Classifies Java files containing a MAC check by where the combining coefficients come from:

- `SAFE_FRESH` — the check runs a coin toss or builds the generator itself;
- `CANDIDATE` — the coefficients come from a generator/seed established before the check;
- `OTHER` — check found, source not recognized.

```bash
python audit.py --src path/to/suite/spdz2k/src/main/java --src path/to/suite/spdz/src/main/java
```

Validated on the FRESCO checkout at `f8383e6`: `Spdz2kMacCheckComputation` is a candidate
(coefficients from the setup-time joint generator), while `SpdzMacCheckProtocol` and
`SpdzRoundSynchronization` in the mod-p suite are fresh (coin toss inside the check). This
matches the manual audit in the paper.

## Scope and limits

- The tools automate (a) solving and verifying the algebraic bypass and (b) the textual
  classification of coefficient sources. They do **not** discover which shares a party can
  tamper with, the protocol step at which tampering happens, or the batch boundaries; those
  are configuration inputs obtained by reading the protocol. Calling the result "fully
  automated attack discovery" would overstate it.
- `synth.py` models the acceptance condition as the linear congruence. The correction-term
  identity behind that model is verified separately in the paper's appendix and tests; the
  tool does not re-derive it from implementation source.
- `audit.py` is a textual heuristic, not a data-flow analysis. Its output is a candidate list
  for a human, not a verdict.
- The recorded FRESCO coefficients are parsed from the project's run logs; the checker does
  not ship the DRBG seed or re-generate the stream itself.


## `binding.py` — missing-binding decider (MASCOT-style checks)

A check whose first stage ignores the shares (masked value and MACs computed from the input
values while the shares are sent separately) passes for any deviation `e`. The later check
that opens the element accepts iff `sum_i m_i e_i = 0` for its masks `m`. `binding.py`
separates the two conditions and decides attackability:

```bash
python binding.py --masks 45747,6372 --field 65519
python binding.py --masks 45747 --field 65519                       # single value: bound
python binding.py --masks 123,456,789,1011 --ring-exponent 128 --positions 2,3
python binding.py --masks 45747,6372 --field 65519 --missing-binding false
```

Validation on the MASCOT probe data (`inputs [11, 22]`, opened `[6383, 19794]`): the tool
reproduces the observed deltas `[6372, 19772]` exactly. The single-value case and the
`--missing-binding false` case are both reported as not attackable, matching the argument that
one opening binds.

## `emit_junit.py` and `verify.py` — synthesis -> execute -> confirm

`emit_junit.py` writes a JUnit class that captures the joint seed, recomputes the coefficient
stream, solves the two-position kernel vector with `BigInteger` arithmetic, tampers the shares
of the two computed results (sum and product of 20 and 30), and prints markers.
`verify.py` copies the class into the checkout, runs Maven, parses the markers, writes
`artifact/synth/verify-report.json`, and removes the generated class.

```bash
python verify.py --fresco-root path/to/fresco --batch 4
```

Recorded result: honest execution opens `[50, 600]`; the tampered run is accepted
(`status=1`) and opens two different values; `confirmed: true`, Maven exit 0. The seed is
fresh in each run, so the two wrong values differ between runs; the marker and the report
are the evidence, not the specific numbers.

## Limits of the extension

- `binding.py` takes the masks and the missing-binding precondition as inputs; it does not
  extract them from source. The first stage is a protocol-level property established by
  reading the input protocol.
- The emitter targets the one integration (FRESCO SPDZ2k sum/product); a different protocol
  needs a different template. The algebraic part (kernel solve) is reused unchanged.
