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
import dk.alexandra.fresco.suite.spdz2k.resource.Spdz2kResourcePool;
import dk.alexandra.fresco.suite.spdz2k.resource.Spdz2kResourcePoolImpl;
import dk.alexandra.fresco.suite.spdz2k.resource.storage.Spdz2kDummyDataSupplier;
import dk.alexandra.fresco.suite.spdz2k.resource.storage.Spdz2kOpenedValueStoreImpl;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.junit.Test;

/** 研究用：测量修复中"每检查一次抛币"的开销。 */
public class TestSpdz2kMacCheckOverhead
    extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static final int OPENS = 500;
  private static final int ROUNDS = 10;

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
    resourcePool.initializeJointRandomness(networkSupplier, AesCtrDrbg::new, 32);
    return resourcePool;
  }

  @Override
  protected ProtocolSuiteNumeric<Spdz2kResourcePool<CompUInt128>> createProtocolSuite() {
    return new Spdz2kProtocolSuiteK64();
  }

  @Test
  public void overhead() {
    runTest(new Opens<>(), EvaluationStrategy.SEQUENTIAL_BATCHED, 3);
  }

  private static class Opens<ResourcePoolT extends Spdz2kResourcePool<CompUInt128>>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {
    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {
      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                return producer.seq(
                    seq -> {
                      List<DRes<List<BigInteger>>> outs = new ArrayList<>();
                      for (int round = 0; round < ROUNDS; round++) {
                        List<DRes<SInt>> vals = new ArrayList<>();
                        for (int i = 0; i < OPENS; i++) {
                          vals.add(seq.numeric().input(BigInteger.valueOf(round * OPENS + i + 1), 1));
                        }
                        DRes<List<BigInteger>> roundOut = seq.par(
                            par -> {
                              List<DRes<BigInteger>> opened = new ArrayList<>();
                              for (DRes<SInt> v : vals) {
                                opened.add(par.numeric().open(v));
                              }
                              return () -> {
                                List<BigInteger> r = new ArrayList<>();
                                for (DRes<BigInteger> o : opened) {
                                  r.add(o.out());
                                }
                                return r;
                              };
                            });
                        outs.add(roundOut);
                      }
                      return () -> {
                        List<BigInteger> r = new ArrayList<>();
                        for (DRes<List<BigInteger>> o : outs) {
                          r.addAll(o.out());
                        }
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
