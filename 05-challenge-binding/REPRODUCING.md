# Core reproduction recipe

The following is manuscript Appendix B, copied as documentation on 2026-11-03. Run its PowerShell recipe from the repository root, the directory containing `05-challenge-binding/`. It uses unchanged existing test sources and the supplied patch. Results are retained in `05-challenge-binding/data/verification-2026-11-03/`; packaging did not rerun Maven. Review command-initialization differences appear in that directory's `run-manifest.json`.

## Appendix B: Minimal reproduction recipe for the core experiment

### B.1. Environment and scope

This recipe uses the present `05-challenge-binding/` layout and a separate checkout of FRESCO commit `f8383e6aead6b44d44b798553aaf0bcaccd81dab`. It covers the message-level opening experiment and the recorded candidate-patch comparison. It does not invoke the broader `run_all.py` harness or depend on its missing historical source snapshots.

The retained message-level report identifies Eclipse Temurin OpenJDK `21.0.11+10-LTS` on Windows 11 amd64. The command printed in `code/artifact/kernel/kernel/messagelevel/run.log` invokes a distribution directory named `apache-maven-3.9.9`; an independent Maven version banner was not retained. Use JDK 21 and Maven 3.9.9 to match this recorded environment, and retain the actual version output for a new run. The pinned parent POM sets Java source/target 1.8, but `lib/common/pom.xml` overrides them to 10; Java 8 alone is therefore insufficient for this reactor. The inspected POMs do not enforce a Maven minimum. These are build declarations and historical environment records, not a newly measured compatibility matrix. [Pinned parent POM](https://github.com/aicis/fresco/blob/f8383e6aead6b44d44b798553aaf0bcaccd81dab/pom.xml), [common-module POM](https://github.com/aicis/fresco/blob/f8383e6aead6b44d44b798553aaf0bcaccd81dab/lib/common/pom.xml).

The commands below are for PowerShell, with Git, JDK and Maven on `PATH`, starting in the directory containing `05-challenge-binding/`. They create a uniquely named reproduction directory and an isolated Maven repository. Initial dependency retrieval requires network access. The core commands were executed during the clean-checkout verification described in Section 6.2. That run used the downloaded Maven executable and an explicit isolated review directory in place of the PATH lookup and GUID-named directory below; the message-level and patch-comparison blocks were extracted from the manuscript without changing the test code or POMs. Its inputs and results are retained in `data/verification-2026-11-03/`.

### B.2. Pinned checkout and dependency build

```powershell
$packageRoot = (Resolve-Path -LiteralPath './05-challenge-binding').Path
$pin = 'f8383e6aead6b44d44b798553aaf0bcaccd81dab'
$reproRoot = Join-Path (Get-Location).Path ('fresco-repro-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $reproRoot -ErrorAction Stop | Out-Null
$frescoRoot = Join-Path $reproRoot 'fresco'
$mavenCache = Join-Path $reproRoot 'm2'

git clone --no-checkout https://github.com/aicis/fresco.git $frescoRoot
if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
git -C $frescoRoot checkout --detach $pin
if ($LASTEXITCODE -ne 0) { throw 'Pinned checkout failed' }
$actualPin = (git -C $frescoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualPin -ne $pin) { throw 'Revision mismatch' }

$mvnExe = (Get-Command mvn.cmd -ErrorAction Stop).Source
& $mvnExe --version 2>&1 | Tee-Object -FilePath (Join-Path $reproRoot 'maven-version.log')
if ($LASTEXITCODE -ne 0) { throw 'Cannot query Maven version' }
java -version 2>&1 | Tee-Object -FilePath (Join-Path $reproRoot 'java-version.log')
if ($LASTEXITCODE -ne 0) { throw 'Cannot query Java version' }

Set-Location -LiteralPath $frescoRoot
$mavenArgs = @('-B', '-ntp', "-Dmaven.repo.local=$mavenCache")
& $mvnExe @mavenArgs -pl suite/spdz2k -am -DskipTests install 2>&1 |
    Tee-Object -FilePath (Join-Path $reproRoot 'bootstrap.log')
if ($LASTEXITCODE -ne 0) { throw 'Dependency build failed; inspect bootstrap.log' }
```

`-am` builds the selected module's reactor dependencies. The SPDZ2k POM depends on `core`, `common`, and `commitment`, including the `core` and `common` test JARs. Those test utilities are needed by the probe. `-DskipTests` skips execution while preserving test compilation and test-JAR packaging; replacing it with `-Dmaven.test.skip=true` can remove required test artifacts. The installation is to the separate local repository; no deployment or publishing goal is used. [Pinned SPDZ2k POM](https://github.com/aicis/fresco/blob/f8383e6aead6b44d44b798553aaf0bcaccd81dab/suite/spdz2k/pom.xml), [Maven reactor options](https://maven.apache.org/guides/mini/guide-multiple-modules.html), [Maven test-skipping semantics](https://maven.apache.org/surefire/maven-surefire-plugin/examples/skipping-tests.html).

### B.3. Message-level probe and result markers

```powershell
$kernelRoot = Join-Path $packageRoot 'code/artifact/kernel/kernel'
$testPackage = 'dk/alexandra/fresco/suite/spdz2k/protocols/computations'
$testDir = Join-Path $frescoRoot ('suite/spdz2k/src/test/java/' + $testPackage)
New-Item -ItemType Directory -Path $testDir -Force -ErrorAction Stop | Out-Null
$messageTest = Join-Path $kernelRoot 'messagelevel/TestKernelMessageLevel.java'
Copy-Item -LiteralPath $messageTest -Destination $testDir -ErrorAction Stop
Get-FileHash -Algorithm SHA256 -LiteralPath $messageTest |
    Format-List | Out-File -FilePath (Join-Path $reproRoot 'test-source-hash.txt')

& $mvnExe @mavenArgs -pl suite/spdz2k '-Dtest=TestKernelMessageLevel' test 2>&1 |
    Tee-Object -FilePath (Join-Path $reproRoot 'message-level.log')
$messageExit = $LASTEXITCODE
Select-String -LiteralPath (Join-Path $reproRoot 'message-level.log') `
    -Pattern '^MSGLVL_(HONEST|TAMPER|CONTROL)_RESULT'
if ($messageExit -ne 0) { throw 'Message-level test command failed; inspect its log' }

$resultText = Get-Content -LiteralPath (Join-Path $reproRoot 'message-level.log') -Raw
if ($resultText -match '(?m)^MSGLVL_(HONEST|TAMPER)_RESULT (blocked|error)') {
    throw 'An honest or tampered execution did not complete normally'
}
if ($resultText -notmatch 'MSGLVL_HONEST_RESULT status=0 opened=\[50, 600\]' -or
    $resultText -notmatch 'MSGLVL_CONTROL_RESULT blocked') {
    throw 'Required honest or negative-control evidence is absent'
}
$tamperMatches = [regex]::Matches($resultText,
    'MSGLVL_TAMPER_RESULT status=1 opened=\[([0-9]+),\s*([0-9]+)\]')
if ($tamperMatches.Count -ne 3) { throw 'Expected three normal tampered executions' }
$outputModulus = [System.Numerics.BigInteger]::Parse('18446744073709551616')
foreach ($tamperMatch in $tamperMatches) {
    $observedSum = [System.Numerics.BigInteger]::Parse($tamperMatch.Groups[1].Value)
    $observedProduct = [System.Numerics.BigInteger]::Parse($tamperMatch.Groups[2].Value)
    $functionalResidual = (($observedProduct - 20 * ($observedSum - 20)) %
        $outputModulus + $outputModulus) % $outputModulus
    if ($functionalResidual -eq 0) { throw 'This pair does not demonstrate the claimed violation' }
    Write-Output "Nonzero functional residual: $functionalResidual"
}
```

The current packaged class has five test methods: an honest run, three-party tampering, two- and four-party tampering, and a three-party non-kernel control. Each method initializes its own fresh joint randomness. The original initial log contains three methods, whereas the later multiparty record contains five; this code/layout recipe targets the packaged five-method class.

The expected evidence is a normal `MSGLVL_HONEST_RESULT status=0 opened=[50, 600]`, normal `MSGLVL_TAMPER_RESULT status=1 opened=[S, P]` lines with changed outputs, and `MSGLVL_CONTROL_RESULT blocked`. The tampered values vary with the seed; `status=1` is a test tamper flag, not an exit code. A normal result line is printed only after `runTest` returns. A tampered `blocked` or `error` line is not an accepted forgery, even if the existing test assertions happen to pass. Retain the entire log and Maven exit code, and require no such tampered failure line. For the functional-integrity interpretation, also evaluate the relation in Section 4: with honest input 20, any lawful corrupt input requires $P-20(S-20)=0\pmod{2^{64}}$. The retained main tampered result violates it.

The test uses dummy preprocessing and a shared static result slot; it does not preserve a separate final result for each honest party. Its source and normal-return markers support the limited message-level claim described in Section 4. Its stream-replay helper requests four coefficients because it accounts for two multiplication openings followed by two final-output openings; this must not be read as a claim that the four openings form one MAC-check batch.

### B.4. Candidate patch comparison

Copy the old disclosed suite to the same test package and first run it against the unmodified pinned source. This provides a local pre-patch record; the oracle limitations identified in Section 4 still apply.

```powershell
$disclosedTest = Join-Path $kernelRoot 'disclosed/TestSpdz2kMacCheckCancellation.java'
Copy-Item -LiteralPath $disclosedTest -Destination $testDir -ErrorAction Stop
& $mvnExe @mavenArgs -pl suite/spdz2k '-Dtest=TestSpdz2kMacCheckCancellation' test 2>&1 |
    Tee-Object -FilePath (Join-Path $reproRoot 'disclosed-original.log')
if ($LASTEXITCODE -ne 0) { throw 'Original-suite command failed; inspect its log' }

$patchFile = Join-Path $kernelRoot 'disclosed/fix.patch'
git apply --check $patchFile
if ($LASTEXITCODE -ne 0) { throw 'Patch does not apply to this checkout' }
git apply $patchFile
if ($LASTEXITCODE -ne 0) { throw 'Patch application failed' }
git diff --name-only | Tee-Object -FilePath (Join-Path $reproRoot 'patched-files.txt')

& $mvnExe @mavenArgs -pl suite/spdz2k '-Dtest=TestSpdz2kMacCheckCancellation' test 2>&1 |
    Tee-Object -FilePath (Join-Path $reproRoot 'disclosed-patched.log')
$patchedExit = $LASTEXITCODE
Write-Output "Patched-suite exit code: $patchedExit"
$reportName = 'dk.alexandra.fresco.suite.spdz2k.protocols.computations.' +
    'TestSpdz2kMacCheckCancellation.txt'
$reportPath = Join-Path $frescoRoot ('suite/spdz2k/target/surefire-reports/' + $reportName)
Select-String -LiteralPath $reportPath -Pattern 'Tests run:|Mac check failed'
```

The patch changes four production files: `Spdz2kMacCheckComputation.java`, `Spdz2kResourcePool.java`, `Spdz2kResourcePoolImpl.java`, and `Spdz2kRoundSynchronization.java`. It derives per-check randomness through `CoinTossingComputation` and the existing commitment machinery. Test copies are additional untracked inputs; the patch does not alter their assertions or the POMs.

The retained patched-suite outcome is eleven tests, zero assertion failures, seven errors with `MaliciousException: Mac check failed`, and four completed honest baselines. A nonzero Maven exit is expected for that historical outcome because the old attack tests still expect acceptance. It is not, by itself, mitigation evidence: distinguish these seven MAC-check rejections from compilation failures, missing dependencies, or unrelated exceptions. The historical text report is `code/artifact/kernel/kernel/disclosed/dk.alexandra.fresco.suite.spdz2k.protocols.computations.TestSpdz2kMacCheckCancellation.txt`. Use it for the reported result. The adjacent historical sanitized XML contains unescaped path placeholders and cannot be assumed machine-parseable. The valid XML reports from the dated clean-checkout verification are separately retained in `data/verification-2026-11-03/reports/`. Preserve newly generated logs/reports as a new execution record rather than replacing the retained evidence. The patch remains a candidate mitigation with the security limits in Section 4.

### B.5. Scope of the auxiliary tool reports

The `binding.py` report demonstrates the recorded nonzero two-mask field instance, masks `[45747, 6372]` modulo 65519 and witness `[6372, 19772]`. The present implementation is not a complete binding decision procedure for arbitrary supplied masks or power-of-two rings: zero-mask cases and one-position zero-divisor cases are not handled correctly. Accordingly, no generic soundness, completeness, or single-position binding claim is inferred from it.

The synthesis reports establish their explicitly checked weighted residual and low-part changes. Their field named `kernel_multiplicity_at_a` returns the positive kernel period $M/\gcd(r_a,M)$ for the single-coefficient multiplication map, not its kernel cardinality $\gcd(r_a,M)$. When the coefficient is a unit, the reported period is $M$, representing the zero residue rather than a nonzero kernel element. This field is not used as a multiplicity or an attack-probability estimate in the manuscript.
