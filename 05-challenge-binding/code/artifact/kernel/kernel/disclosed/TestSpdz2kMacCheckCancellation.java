package dk.alexandra.fresco.suite.spdz2k.protocols.computations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.sce.evaluator.EvaluationStrategy;
import dk.alexandra.fresco.framework.util.AesCtrDrbg;
import dk.alexandra.fresco.framework.util.Drbg;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.suite.ProtocolSuiteNumeric;
import dk.alexandra.fresco.suite.spdz2k.AbstractSpdz2kTest;
import dk.alexandra.fresco.suite.spdz2k.Spdz2kProtocolSuiteK64;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt128;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt128Factory;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUIntFactory;
import dk.alexandra.fresco.suite.spdz2k.datatypes.Spdz2kSInt;
import dk.alexandra.fresco.suite.spdz2k.resource.Spdz2kResourcePool;
import dk.alexandra.fresco.suite.spdz2k.resource.Spdz2kResourcePoolImpl;
import dk.alexandra.fresco.suite.spdz2k.resource.storage.Spdz2kDummyDataSupplier;
import dk.alexandra.fresco.suite.spdz2k.resource.storage.Spdz2kOpenedValueStoreImpl;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import org.junit.Test;

/**
 * 研究用：SPDZ2k 的 MAC 检查在系数可预测时能否被绕过。
 *
 * <p>把 joint DRBG 固定为公开种子（等价于真实实现里公开抛币得到的种子），
 * 腐败方在打开前算出本批系数，构造误差 δ 使 Σ r_i δ_i ≡ 0 (mod 2^128)，
 * 再修改自己打开共享的低 64 位。
 *
 * <p>两个测试：baseline 不修改（输出应为 111/222/333）；
 * attack 修改（检查应通过，但输出不是 111/222/333）。
 */
public class TestSpdz2kMacCheckCancellation
    extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static volatile byte[] capturedSeed;
  private static final BigInteger MOD = BigInteger.ONE.shiftLeft(128);
  private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);

  private static volatile List<BigInteger> lastOpened;
  private static volatile int[] lastTriple;
  private static volatile BigInteger[] lastDeltas;

  @Override
  protected Spdz2kResourcePool<CompUInt128> createResourcePool(
      int playerId, int noOfParties, Supplier<Network> networkSupplier) {
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    Spdz2kResourcePool<CompUInt128> resourcePool =
        new Spdz2kResourcePoolImpl<>(
            playerId,
            noOfParties,
            null,
            new Spdz2kOpenedValueStoreImpl<>(),
            new Spdz2kDummyDataSupplier<>(playerId, noOfParties, factory.createRandom(), factory),
            factory);
    // 忠实建模：种子仍来自真实抛币，只是被记录下来（任何参与方都能从公开的
    // 抛币开放份额算出它）。
    resourcePool.initializeJointRandomness(
        networkSupplier,
        seed -> {
          capturedSeed = seed.clone();
          return new AesCtrDrbg(seed);
        },
        32);
    return resourcePool;
  }

  @Override
  protected ProtocolSuiteNumeric<Spdz2kResourcePool<CompUInt128>> createProtocolSuite() {
    return new Spdz2kProtocolSuiteK64();
  }

  private static List<BigInteger> expected(int k) {
    List<BigInteger> r = new ArrayList<>();
    for (int i = 0; i < k; i++) {
      r.add(BigInteger.valueOf(i + 1));
    }
    return r;
  }

  @Test
  public void baseline() {
    lastOpened = null;
    runTest(new TestCancel<>(false, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    assertEquals(expected(8), lastOpened);
  }

  private static List<BigInteger> corruptedExpected(int k) {
    List<BigInteger> r = new ArrayList<>(expected(k));
    if (lastTriple != null && lastDeltas != null) {
      for (int t = 0; t < lastTriple.length; t++) {
        int idx = lastTriple[t];
        r.set(idx, r.get(idx).add(lastDeltas[t]).mod(TWO_64));
      }
    }
    return r;
  }

  @Test
  public void attack() {
    lastOpened = null;
    lastTriple = null;
    lastDeltas = null;
    runTest(new TestCancel<>(true, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    assertNotEquals("打开值未被篡改", expected(8), lastOpened);
    assertEquals("被篡改的打开值应恰为 真值+δ mod 2^64", corruptedExpected(8), lastOpened);
  }

  @Test
  public void baselineTwoParties() {
    lastOpened = null;
    runTest(new TestCancel<>(false, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 2);
    assertEquals(expected(8), lastOpened);
  }

  @Test
  public void attackTwoParties() {
    lastOpened = null;
    runTest(new TestCancel<>(true, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 2);
    assertNotEquals("打开值未被篡改", expected(8), lastOpened);
  }

  @Test
  public void attackCheaterOne() {
    lastOpened = null;
    runTest(new TestCancel<>(true, 8, 1), EvaluationStrategy.SEQUENTIAL_BATCHED, 4);
    assertNotEquals("打开值未被篡改", expected(8), lastOpened);
  }

  @Test
  public void baselineFourParties() {
    lastOpened = null;
    runTest(new TestCancel<>(false, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 4);
    assertEquals(expected(8), lastOpened);
  }

  @Test
  public void attackFourParties() {
    lastOpened = null;
    runTest(new TestCancel<>(true, 8), EvaluationStrategy.SEQUENTIAL_BATCHED, 4);
    assertNotEquals("打开值未被篡改", expected(8), lastOpened);
  }

  @Test
  public void attackComputedProducts() {
    lastOpened = null;
    lastTriple = null;
    lastDeltas = null;
    runTest(new TestProducts<>(true), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    List<BigInteger> out = lastOpened;
    assertNotEquals("计算值未被篡改", computedExpected(8), out);
  }

  private static List<BigInteger> computedExpected(int k) {
    List<BigInteger> r = new ArrayList<>();
    for (int i = 0; i < k; i++) {
      r.add(BigInteger.valueOf((i + 1) + (i + 2)));
    }
    return r;
  }

  @Test
  public void attackMultiCheck() {
    lastOpened = null;
    lastTriple = null;
    lastDeltas = null;
    runTest(new TestMultiCheck<>(), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
  }

  @Test
  public void baselineLarge() {
    lastOpened = null;
    runTest(new TestCancel<>(false, 100), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    assertEquals(expected(100), lastOpened);
  }

  @Test
  public void attackLarge() {
    lastOpened = null;
    runTest(new TestCancel<>(true, 100), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    assertNotEquals("打开值未被篡改", expected(100), lastOpened);
  }

  private static class TestCancel<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    private final boolean corrupt;
    private final int k;
    private final int cheater;

    TestCancel(boolean corrupt, int k) {
      this(corrupt, k, 2);
    }

    TestCancel(boolean corrupt, int k, int cheater) {
      this.corrupt = corrupt;
      this.k = k;
      this.cheater = cheater;
    }

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {
      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                List<DRes<SInt>> vals = new ArrayList<>();
                for (int i = 0; i < k; i++) {
                  vals.add(numeric.input(BigInteger.valueOf(i + 1), 1));
                }
                return producer.par(
                    par -> {
                      int me = par.getBasicNumericContext().getMyId();
                      if (corrupt && me == cheater) {
                        List<BigInteger> coeffs = firstCoefficients(k);
                        Cancellation c = findCancellation(coeffs);
                        int[] triple = c.triple;
                        BigInteger[] deltas = c.deltas;
                        lastTriple = triple;
                        lastDeltas = deltas;
                        for (int t = 0; t < 3; t++) {
                          int idx = triple[t];
                          Spdz2kSInt<CompUInt128> old =
                              (Spdz2kSInt<CompUInt128>) vals.get(idx).out();
                          CompUInt128 newShare =
                              old.getShare().add(new CompUInt128(deltas[t]));
                          Spdz2kSInt<CompUInt128> modified =
                              new Spdz2kSInt<>(newShare, old.getMacShare());
                          vals.set(idx, (DRes<SInt>) () -> modified);
                        }
                      }
                      List<DRes<BigInteger>> outs = new ArrayList<>();
                      for (DRes<SInt> v : vals) {
                        outs.add(par.numeric().open(v));
                      }
                      return () -> {
                        List<BigInteger> r = new ArrayList<>();
                        for (DRes<BigInteger> o : outs) {
                          r.add(o.out());
                        }
                        lastOpened = r;
                        return r;
                      };
                    });
              };
          runApplication(app);
        }
      };
    }
  }

  private static class Cancellation {
    final int[] triple;
    final BigInteger[] deltas;

    Cancellation(int[] triple, BigInteger[] deltas) {
      this.triple = triple;
      this.deltas = deltas;
    }
  }

  private static Cancellation findCancellation(List<BigInteger> coeffs) {
    int tries = 0;
    for (int i = 0; i < coeffs.size() && tries < 200; i++) {
      for (int j = i + 1; j < coeffs.size() && tries < 200; j++) {
        for (int l = j + 1; l < coeffs.size() && tries < 200; l++) {
          BigInteger g = egcd(egcd(coeffs.get(i), coeffs.get(j))[0], coeffs.get(l))[0];
          if (!MOD.mod(g).equals(BigInteger.ZERO)) {
            continue;
          }
          tries++;
          try {
            BigInteger[] d = solveKnapsack(
                Arrays.asList(coeffs.get(i), coeffs.get(j), coeffs.get(l)));
            return new Cancellation(new int[] {i, j, l}, d);
          } catch (IllegalStateException e) {
            // 换一组三元组
          }
        }
      }
    }
    throw new IllegalStateException("no triple with a boxed solution after " + tries + " tries");
  }

  private static List<BigInteger> firstCoefficients(int k) {
    Drbg drbg = new AesCtrDrbg(capturedSeed);
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    List<BigInteger> out = new ArrayList<>();
    for (int i = 0; i < k; i++) {
      byte[] bytes = new byte[factory.getHighBitLength() / Byte.SIZE];
      drbg.nextBytes(bytes);
      out.add(factory.deserialize(bytes).toBigInteger());
    }
    return out;
  }

  // ---- 有界背包：Σ c_i δ_i = 2^128，0 ≤ δ_i < 2^64 ----

  private static BigInteger[] egcd(BigInteger a, BigInteger b) {
    if (b.signum() == 0) {
      return new BigInteger[] {a, BigInteger.ONE, BigInteger.ZERO};
    }
    BigInteger[] r = egcd(b, a.mod(b));
    return new BigInteger[] {r[0], r[2], r[1].subtract(a.divide(b).multiply(r[2]))};
  }

  private static boolean inBox(BigInteger x) {
    return x.signum() >= 0 && x.compareTo(TWO_64) < 0;
  }

  /** 解 Σ c_i δ_i ≡ 0 (mod 2^128)，0 ≤ δ_i < 2^64：二维丢番图 + 搜索 δ3。 */
  private static BigInteger[] solveKnapsack(List<BigInteger> c) {
    BigInteger c1 = c.get(0);
    BigInteger c2 = c.get(1);
    BigInteger c3 = c.get(2);
    BigInteger[] e12 = egcd(c1, c2);
    BigInteger g12 = e12[0];
    if (g12.signum() == 0) {
      throw new IllegalStateException("zero coefficient");
    }
    for (int targetIdx = 1; targetIdx <= 2; targetIdx++) {
      BigInteger target = MOD.multiply(BigInteger.valueOf(targetIdx));
      for (int d3 = 0; d3 < 5000; d3++) {
        BigInteger T = target.subtract(c3.multiply(BigInteger.valueOf(d3)));
        BigInteger[] qr = T.divideAndRemainder(g12);
        if (qr[1].signum() != 0) {
          continue;
        }
        BigInteger k = qr[0];
        BigInteger X = e12[1].multiply(k);
        BigInteger Y = e12[2].multiply(k);
        BigInteger step1 = c2.divide(g12);
        BigInteger step2 = c1.divide(g12);
        if (step1.signum() == 0 || step2.signum() == 0) {
          continue;
        }
        BigInteger t0 = X.negate().divide(step1);
        for (int dt = -3; dt <= 3; dt++) {
          BigInteger tt = t0.add(BigInteger.valueOf(dt));
          BigInteger d1 = X.add(step1.multiply(tt));
          BigInteger d2 = Y.subtract(step2.multiply(tt));
          if (inBox(d1) && inBox(d2)) {
            return new BigInteger[] {d1, d2, BigInteger.valueOf(d3)};
          }
        }
      }
    }
    // 回退：只用两个值（第三个 δ=0）
    int[][] pairs = {{0, 1}, {0, 2}, {1, 2}};
    for (int[] pr : pairs) {
      BigInteger[] d = solvePair(c.get(pr[0]), c.get(pr[1]));
      if (d != null) {
        BigInteger[] full = new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};
        full[pr[0]] = d[0];
        full[pr[1]] = d[1];
        return full;
      }
    }
    throw new IllegalStateException("no solution in box");
  }

  private static BigInteger[] solvePair(BigInteger a, BigInteger b) {
    BigInteger[] e = egcd(a, b);
    BigInteger g = e[0];
    if (g.signum() == 0) {
      return null;
    }
    for (int targetIdx = 1; targetIdx <= 2; targetIdx++) {
      BigInteger target = MOD.multiply(BigInteger.valueOf(targetIdx));
      BigInteger[] qr = target.divideAndRemainder(g);
      if (qr[1].signum() != 0) {
        continue;
      }
      BigInteger k = qr[0];
      BigInteger X = e[1].multiply(k);
      BigInteger Y = e[2].multiply(k);
      BigInteger step1 = b.divide(g);
      BigInteger step2 = a.divide(g);
      if (step1.signum() == 0 || step2.signum() == 0) {
        continue;
      }
      BigInteger t0 = X.negate().divide(step1);
      for (int dt = -4; dt <= 4; dt++) {
        BigInteger tt = t0.add(BigInteger.valueOf(dt));
        BigInteger d1 = X.add(step1.multiply(tt));
        BigInteger d2 = Y.subtract(step2.multiply(tt));
        if (inBox(d1) && inBox(d2)) {
          return new BigInteger[] {d1, d2};
        }
      }
    }
    return null;
  }

  private static BigInteger divideRound(BigInteger num, BigInteger den) {
    BigInteger[] qr = num.divideAndRemainder(den);
    BigInteger q = qr[0];
    if (qr[1].abs().shiftLeft(1).compareTo(den.abs()) >= 0) {
      q = q.add(BigInteger.valueOf(num.signum() * den.signum()));
    }
    return q;
  }

  /** 打开的是计算得到的和，而不是直接输入。 */
  private static class TestProducts<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    private final boolean corrupt;

    TestProducts(boolean corrupt) {
      this.corrupt = corrupt;
    }

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {
      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                List<DRes<SInt>> as = new ArrayList<>();
                List<DRes<SInt>> bs = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                  as.add(numeric.input(BigInteger.valueOf(i + 1), 1));
                  bs.add(numeric.input(BigInteger.valueOf(i + 2), 1));
                }
                return producer.seq(
                    seq -> {
                      List<DRes<SInt>> prods = new ArrayList<>();
                      for (int i = 0; i < 8; i++) {
                        prods.add(seq.numeric().mult(as.get(i), bs.get(i)));
                      }
                      return seq.par(
                          par -> {
                            int me = par.getBasicNumericContext().getMyId();
                            if (corrupt && me == 2) {
                              // 第一次检查消费 16 个系数（16 个输入打开），
                              // 乘积的检查是第二次，系数从偏移 16 开始。
                              List<BigInteger> coeffs = firstCoefficients(24).subList(16, 24);
                              Cancellation c = findCancellation(coeffs);
                              lastTriple = c.triple;
                              lastDeltas = c.deltas;
                              for (int t = 0; t < c.triple.length; t++) {
                                int idx = c.triple[t];
                                Spdz2kSInt<CompUInt128> old =
                                    (Spdz2kSInt<CompUInt128>) prods.get(idx).out();
                                Spdz2kSInt<CompUInt128> modified =
                                    new Spdz2kSInt<>(
                                        old.getShare().add(new CompUInt128(c.deltas[t])),
                                        old.getMacShare());
                                prods.set(idx, (DRes<SInt>) () -> modified);
                              }
                            }
                            List<DRes<BigInteger>> outs = new ArrayList<>();
                            for (DRes<SInt> v : prods) {
                              outs.add(par.numeric().open(v));
                            }
                            return () -> {
                              List<BigInteger> r = new ArrayList<>();
                              for (DRes<BigInteger> o : outs) {
                                r.add(o.out());
                              }
                              lastOpened = r;
                              return r;
                            };
                          });
                    });
              };
          runApplication(app);
        }
      };
    }
  }

  /** 200 个打开值；内批 128，攻击第二批（索引 >= 128），系数从 128 起。 */
  private static class TestMultiCheck<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {
      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                List<DRes<SInt>> vals = new ArrayList<>();
                for (int i = 0; i < 200; i++) {
                  vals.add(numeric.input(BigInteger.valueOf(i + 1), 1));
                }
                return producer.par(
                    par -> {
                      int me = par.getBasicNumericContext().getMyId();
                      if (me == 2) {
                        List<BigInteger> coeffs = firstCoefficients(200);
                        List<BigInteger> tail = coeffs.subList(128, 200);
                        Cancellation c = findCancellation(tail);
                        for (int t = 0; t < c.triple.length; t++) {
                          int idx = 128 + c.triple[t];
                          Spdz2kSInt<CompUInt128> old =
                              (Spdz2kSInt<CompUInt128>) vals.get(idx).out();
                          Spdz2kSInt<CompUInt128> modified =
                              new Spdz2kSInt<>(
                                  old.getShare().add(new CompUInt128(c.deltas[t])),
                                  old.getMacShare());
                          vals.set(idx, (DRes<SInt>) () -> modified);
                        }
                      }
                      List<DRes<BigInteger>> outs = new ArrayList<>();
                      for (DRes<SInt> v : vals) {
                        outs.add(par.numeric().open(v));
                      }
                      return () -> {
                        List<BigInteger> r = new ArrayList<>();
                        for (DRes<BigInteger> o : outs) {
                          r.add(o.out());
                        }
                        lastOpened = r;
                        return r;
                      };
                    });
              };
          runApplication(app);
        }
      };
    }
  }
}
