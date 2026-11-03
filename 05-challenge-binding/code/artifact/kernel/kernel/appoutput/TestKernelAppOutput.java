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
 * Research probe: a corrupt party makes the *computed outputs* of a concrete SPDZ2k task wrong
 * (sum and product of two inputs) while the batched MAC check accepts the openings.
 *
 * <p>The corrupt party keeps its MAC shares and replaces its authenticated-value shares of the two
 * computed results by the kernel vector e = (r_2, -r_1), so the residual cancels.
 */
public class TestKernelAppOutput extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static final BigInteger MOD = BigInteger.ONE.shiftLeft(128);
  private static volatile byte[] capturedSeed;
  private static volatile List<BigInteger> lastOpened;
  private static volatile int status;
  private static volatile int batchSize = 2;

  @Override
  protected Spdz2kResourcePool<CompUInt128> createResourcePool(
      int playerId, int noOfParties, Supplier<Network> networkSupplier) {
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    Spdz2kResourcePool<CompUInt128> pool =
        new Spdz2kResourcePoolImpl<>(
            playerId,
            noOfParties,
            null,
            new Spdz2kOpenedValueStoreImpl<>(),
            new Spdz2kDummyDataSupplier<>(playerId, noOfParties, factory.createRandom(), factory),
            factory);
    pool.initializeJointRandomness(
        networkSupplier,
        seed -> {
          capturedSeed = seed.clone();
          return new AesCtrDrbg(seed);
        },
        32);
    return pool;
  }

  @Override
  protected ProtocolSuiteNumeric<Spdz2kResourcePool<CompUInt128>> createProtocolSuite() {
    return new Spdz2kProtocolSuiteK64();
  }

  private static List<BigInteger> coefficients(int n) {
    List<BigInteger> out = new ArrayList<>();
    CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
    Drbg drbg = new AesCtrDrbg(capturedSeed);
    for (int i = 0; i < n; i++) {
      byte[] bytes = new byte[factory.getHighBitLength() / Byte.SIZE];
      drbg.nextBytes(bytes);
      out.add(factory.deserialize(bytes).toBigInteger());
    }
    return out;
  }

  private static class App
      extends TestThreadFactory<Spdz2kResourcePool<CompUInt128>, ProtocolBuilderNumeric> {
    private final boolean tamper;

    App(boolean tamper) {
      this.tamper = tamper;
    }

    @Override
    public TestThread<Spdz2kResourcePool<CompUInt128>, ProtocolBuilderNumeric> next() {
      return new TestThread<Spdz2kResourcePool<CompUInt128>, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                DRes<SInt> x1 = numeric.input(BigInteger.valueOf(20), 1);
                DRes<SInt> x2 = numeric.input(BigInteger.valueOf(30), 2);
                return producer.seq(
                    seq -> {
                      Numeric n = seq.numeric();
                      DRes<SInt> sum = n.add(x1, x2);
                      DRes<SInt> product = n.mult(x1, x2);
                      List<DRes<SInt>> values = new ArrayList<>();
                      values.add(sum);
                      values.add(product);
                      return seq.par(
                          par -> {
                            if (tamper && par.getBasicNumericContext().getMyId() == 2) {
                              List<BigInteger> coeffs = coefficients(batchSize);
                              // the two computed results are the last two openings of the batch
                              BigInteger r1 = coeffs.get(batchSize - 2);
                              BigInteger r2 = coeffs.get(batchSize - 1);
                              BigInteger e1 = r2;
                              BigInteger e2 = MOD.subtract(r1);
                              Spdz2kSInt<CompUInt128> s0 =
                                  (Spdz2kSInt<CompUInt128>) values.get(0).out();
                              Spdz2kSInt<CompUInt128> s1 =
                                  (Spdz2kSInt<CompUInt128>) values.get(1).out();
                              Spdz2kSInt<CompUInt128> n0 =
                                  new Spdz2kSInt<>(
                                      s0.getShare().add(new CompUInt128(e1)), s0.getMacShare());
                              Spdz2kSInt<CompUInt128> n1 =
                                  new Spdz2kSInt<>(
                                      s1.getShare().add(new CompUInt128(e2)), s1.getMacShare());
                              values.set(0, (DRes<SInt>) () -> n0);
                              values.set(1, (DRes<SInt>) () -> n1);
                              status = 1;
                            }
                            List<DRes<BigInteger>> outs = new ArrayList<>();
                            for (DRes<SInt> v : values) {
                              outs.add(par.numeric().open(v));
                            }
                            return () -> {
                              List<BigInteger> res = new ArrayList<>();
                              for (DRes<BigInteger> o : outs) {
                                res.add(o.out());
                              }
                              lastOpened = res;
                              return res;
                            };
                          });
                    });
              };
          runApplication(app);
        }
      };
    }
  }

  private void run(boolean tamper, int batch) {
    batchSize = batch;
    lastOpened = null;
    status = 0;
    try {
      runTest(new App(tamper), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        System.out.println((tamper ? "APPOUT_TAMPER" : "APPOUT_HONEST") + "_RESULT blocked");
        return;
      }
      System.out.println((tamper ? "APPOUT_TAMPER" : "APPOUT_HONEST") + "_RESULT error");
      return;
    }
    System.out.println(
        (tamper ? "APPOUT_TAMPER" : "APPOUT_HONEST")
            + "_RESULT status=" + status + " opened=" + lastOpened);
  }

  @Test
  public void honestComputation() {
    run(false, 4);
    boolean ok = lastOpened != null
        && lastOpened.equals(Arrays.asList(BigInteger.valueOf(50), BigInteger.valueOf(600)));
    System.out.println("APPOUT_HONEST_OK " + ok);
    if (!ok) {
      throw new AssertionError("honest output wrong: " + lastOpened);
    }
  }

  @Test
  public void tamperedComputationAccepted() {
    run(true, 4);
    boolean changed = lastOpened != null
        && !lastOpened.equals(Arrays.asList(BigInteger.valueOf(50), BigInteger.valueOf(600)));
    System.out.println("APPOUT_TAMPER_OK " + (status == 1 && changed));
    if (!(status == 1 && changed)) {
      throw new AssertionError("tampered output not observed: status=" + status + " opened=" + lastOpened);
    }
  }
}
