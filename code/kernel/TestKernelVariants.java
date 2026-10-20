package dk.alexandra.fresco.suite.spdz2k.protocols.computations;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.sce.evaluator.EvaluationStrategy;
import dk.alexandra.fresco.framework.util.AesCtrDrbg;
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
import java.util.List;
import java.util.function.Supplier;
import org.junit.Test;

/**
 * 研究用：完整恶意模型下的两个变体。
 *
 * <p>eightValues：8 个打开值，只对前两个施加核向量 e=(r2,-r1)，其余为零。
 * singleStealth：单个打开值，施加 e=M/gcd(r1,M)（只改高位），检查是否接受、输出是否不变。
 */
public class TestKernelVariants extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static volatile byte[] capturedSeed;
  private static final BigInteger MOD = BigInteger.ONE.shiftLeft(128);
  private static volatile List<BigInteger> lastOpened;
  private static volatile int n = 2;
  private static volatile boolean single = false;

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

  private static List<BigInteger> coefficients(int count) {
    List<BigInteger> out = new ArrayList<>();
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    dk.alexandra.fresco.framework.util.Drbg drbg = new AesCtrDrbg(capturedSeed);
    for (int i = 0; i < count; i++) {
      byte[] bytes = new byte[factory.getHighBitLength() / Byte.SIZE];
      drbg.nextBytes(bytes);
      out.add(factory.deserialize(bytes).toBigInteger());
    }
    return out;
  }

  private static class Variant<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    private final int count;
    private final boolean stealth;
    private final boolean control;

    Variant(int count, boolean stealth) {
      this(count, stealth, false);
    }

    Variant(int count, boolean stealth, boolean control) {
      this.count = count;
      this.stealth = stealth;
      this.control = control;
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
                for (int i = 0; i < count; i++) {
                  vals.add(numeric.input(BigInteger.valueOf(i + 1), 1));
                }
                return producer.par(
                    par -> {
                      int me = par.getBasicNumericContext().getMyId();
                      if (me == 2) {
                        List<BigInteger> cs = coefficients(count);
                        if (control) {
                          Spdz2kSInt<CompUInt128> v = (Spdz2kSInt<CompUInt128>) vals.get(0).out();
                          Spdz2kSInt<CompUInt128> nv =
                              new Spdz2kSInt<>(
                                  v.getShare().add(new CompUInt128(BigInteger.ONE)),
                                  v.getMacShare());
                          vals.set(0, (DRes<SInt>) () -> nv);
                          if (count > 1) {
                            Spdz2kSInt<CompUInt128> v1 =
                                (Spdz2kSInt<CompUInt128>) vals.get(1).out();
                            Spdz2kSInt<CompUInt128> nv1 =
                                new Spdz2kSInt<>(
                                    v1.getShare().add(new CompUInt128(BigInteger.ONE)),
                                    v1.getMacShare());
                            vals.set(1, (DRes<SInt>) () -> nv1);
                          }
                        } else if (stealth) {
                          BigInteger r = cs.get(0);
                          BigInteger e = MOD.divide(r.gcd(MOD));
                          if (e.compareTo(MOD) < 0) { // r 为奇数时 e = M 等价于不改
                            Spdz2kSInt<CompUInt128> v =
                                (Spdz2kSInt<CompUInt128>) vals.get(0).out();
                            Spdz2kSInt<CompUInt128> nv =
                                new Spdz2kSInt<>(
                                    v.getShare().add(new CompUInt128(e)), v.getMacShare());
                            vals.set(0, (DRes<SInt>) () -> nv);
                          }
                        } else {
                          BigInteger r1 = cs.get(0);
                          BigInteger r2 = cs.get(1);
                          Spdz2kSInt<CompUInt128> v0 = (Spdz2kSInt<CompUInt128>) vals.get(0).out();
                          Spdz2kSInt<CompUInt128> v1 = (Spdz2kSInt<CompUInt128>) vals.get(1).out();
                          Spdz2kSInt<CompUInt128> n0 =
                              new Spdz2kSInt<>(
                                  v0.getShare().add(new CompUInt128(r2)), v0.getMacShare());
                          Spdz2kSInt<CompUInt128> n1 =
                              new Spdz2kSInt<>(
                                  v1.getShare().add(new CompUInt128(MOD.subtract(r1))),
                                  v1.getMacShare());
                          vals.set(0, (DRes<SInt>) () -> n0);
                          vals.set(1, (DRes<SInt>) () -> n1);
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

  private void run(int count, boolean stealth, String tag) {
    lastOpened = null;
    try {
      runTest(new Variant<>(count, stealth), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println(tag + " blocked");
        return;
      }
      System.out.println(tag + " error");
      return;
    }
    boolean changed = false;
    if (lastOpened != null) {
      for (int i = 0; i < lastOpened.size(); i++) {
        if (!lastOpened.get(i).equals(BigInteger.valueOf(i + 1))) {
          changed = true;
        }
      }
    }
    System.out.println(tag + (changed ? " changed" : " unchanged"));
  }

  @Test
  public void threeValues() {
    run(3, false, "K3_RESULT");
  }

  @Test
  public void fiveValues() {
    run(5, false, "K5_RESULT");
  }

  @Test
  public void eightValues() {
    n = 8;
    run(8, false, "K8_RESULT");
  }

  @Test
  public void singleStealth() {
    single = true;
    run(1, true, "K1_RESULT");
  }

  @Test
  public void eightControl() {
    lastOpened = null;
    try {
      runTest(new Variant<>(8, false, true), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("K8C_RESULT blocked");
        return;
      }
      System.out.println("K8C_RESULT error");
      return;
    }
    System.out.println("K8C_RESULT accepted");
  }

  @Test
  public void pairControl() {
    lastOpened = null;
    try {
      runTest(new Variant<>(2, false, true), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("K2C_RESULT blocked");
        return;
      }
      System.out.println("K2C_RESULT error");
      return;
    }
    System.out.println("K2C_RESULT accepted");
  }

  @Test
  public void singleControl() {
    lastOpened = null;
    try {
      runTest(new Variant<>(1, false, true), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("K1C_RESULT blocked");
        return;
      }
      System.out.println("K1C_RESULT error");
      return;
    }
    System.out.println("K1C_RESULT accepted");
  }
}
