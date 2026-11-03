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
 * 研究用：完整恶意模型下的核向量攻击。
 *
 * <p>误差允许为负（全环），取 e = (r2/g, -r1/g)，g = gcd(r1, r2)。此时
 * r1 e1 + r2 e2 = 0，检查通过；低位发生变化，因此打开值被篡改。
 * 只有当 g 是 2 的幂时才有整数解。打印 KERNEL_RESULT 标记。
 */
public class TestKernelAttack extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static volatile byte[] capturedSeed;
  private static final BigInteger MOD = BigInteger.ONE.shiftLeft(128);
  private static volatile List<BigInteger> lastOpened;
  private static volatile int status; // 1 = 已应用核向量, 2 = gcd 非 2 的幂
  private static volatile List<BigInteger> lastCoeffs;

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

  private static List<BigInteger> coefficients(int n) {
    List<BigInteger> out = new ArrayList<>();
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    dk.alexandra.fresco.framework.util.Drbg drbg = new AesCtrDrbg(capturedSeed);
    for (int i = 0; i < n; i++) {
      byte[] bytes = new byte[factory.getHighBitLength() / Byte.SIZE];
      drbg.nextBytes(bytes);
      out.add(factory.deserialize(bytes).toBigInteger());
    }
    return out;
  }

  private static class TestKernel<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
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
                for (int i = 0; i < 2; i++) {
                  vals.add(numeric.input(BigInteger.valueOf(i + 1), 1));
                }
                return producer.par(
                    par -> {
                      int me = par.getBasicNumericContext().getMyId();
                      if (me == 2) {
                        List<BigInteger> coeffs = coefficients(2);
                        BigInteger r1 = coeffs.get(0);
                        BigInteger r2 = coeffs.get(1);
                        lastCoeffs = coeffs;
                        // 无条件核向量 e = (r2, -r1)：r1*r2 + r2*(-r1) = 0
                        BigInteger e1 = r2;
                        BigInteger e2 = MOD.subtract(r1);
                        Spdz2kSInt<CompUInt128> v0 = (Spdz2kSInt<CompUInt128>) vals.get(0).out();
                        Spdz2kSInt<CompUInt128> v1 = (Spdz2kSInt<CompUInt128>) vals.get(1).out();
                        Spdz2kSInt<CompUInt128> n0 =
                            new Spdz2kSInt<>(
                                v0.getShare().add(new CompUInt128(e1)), v0.getMacShare());
                        Spdz2kSInt<CompUInt128> n1 =
                            new Spdz2kSInt<>(
                                v1.getShare().add(new CompUInt128(e2)), v1.getMacShare());
                        vals.set(0, (DRes<SInt>) () -> n0);
                        vals.set(1, (DRes<SInt>) () -> n1);
                        status = 1;
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

  @Test
  public void kernelAttackFourParties() {
    lastOpened = null;
    lastCoeffs = null;
    status = 0;
    try {
      runTest(new TestKernel<>(), EvaluationStrategy.SEQUENTIAL_BATCHED, 4);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("KERNEL4P_RESULT blocked");
        return;
      }
      System.out.println("KERNEL4P_RESULT error");
      return;
    }
    boolean changed =
        lastOpened != null
            && !lastOpened.equals(
                java.util.Arrays.asList(BigInteger.ONE, BigInteger.valueOf(2)));
    System.out.println(
        "KERNEL4P_RESULT " + (status == 1 && changed ? "success" : (status == 1 ? "nochange" : "nosol")));
  }

  @Test
  public void kernelAttackTwoParties() {
    lastOpened = null;
    lastCoeffs = null;
    status = 0;
    try {
      runTest(new TestKernel<>(), EvaluationStrategy.SEQUENTIAL_BATCHED, 2);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("KERNEL2P_RESULT blocked");
        return;
      }
      System.out.println("KERNEL2P_RESULT error");
      return;
    }
    boolean changed =
        lastOpened != null
            && !lastOpened.equals(
                java.util.Arrays.asList(BigInteger.ONE, BigInteger.valueOf(2)));
    System.out.println(
        "KERNEL2P_RESULT " + (status == 1 && changed ? "success" : (status == 1 ? "nochange" : "nosol")));
  }

  @Test
  public void kernelAttack() {
    lastOpened = null;
    status = 0;
    boolean error = false;
    try {
      runTest(new TestKernel<>(), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println("KERNEL_RESULT blocked");
        return;
      }
      error = true;
    }
    boolean changed =
        lastOpened != null
            && !lastOpened.equals(
                java.util.Arrays.asList(BigInteger.ONE, BigInteger.valueOf(2)));
    if (error) {
      System.out.println("KERNEL_RESULT error");
    } else if (status == 1 && changed) {
      System.out.println("KERNEL_RESULT success coeffs=" + lastCoeffs + " out=" + lastOpened);
    } else if (status == 1) {
      System.out.println("KERNEL_RESULT nochange");
    } else {
      System.out.println("KERNEL_RESULT nosol");
    }
  }
}
