package dk.alexandra.fresco.suite.spdz2k.protocols.computations;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.network.serializers.ByteSerializer;
import dk.alexandra.fresco.framework.sce.evaluator.EvaluationStrategy;
import dk.alexandra.fresco.framework.util.AesCtrDrbg;
import dk.alexandra.fresco.framework.util.Drbg;
import dk.alexandra.fresco.framework.util.OpenedValueStore;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.suite.ProtocolSuiteNumeric;
import dk.alexandra.fresco.suite.spdz2k.AbstractSpdz2kTest;
import dk.alexandra.fresco.suite.spdz2k.Spdz2kProtocolSuiteK64;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt128;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt128Factory;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUIntFactory;
import dk.alexandra.fresco.suite.spdz2k.datatypes.Spdz2kSInt;
import dk.alexandra.fresco.suite.spdz2k.datatypes.UInt;
import dk.alexandra.fresco.suite.spdz2k.protocols.natives.RequiresMacCheck;
import dk.alexandra.fresco.suite.spdz2k.protocols.natives.Spdz2kNativeProtocol;
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
 * Message-level reachability probe.
 *
 * <p>The corrupt party does not replace a local object. Its application appends a native opening
 * protocol that sends the least-significant share of an authenticated element whose share has been
 * shifted by the kernel-vector delta, keeping the original MAC share. Honest parties run the
 * unmodified SPDZ2k code. If the messages are accepted, the modeled hook state is reachable through
 * the protocol's opening messages.
 */
public class TestKernelMessageLevel extends AbstractSpdz2kTest<Spdz2kResourcePool<CompUInt128>> {

  private static final BigInteger MOD = BigInteger.ONE.shiftLeft(128);
  private static volatile byte[] capturedSeed;
  private static volatile List<BigInteger> lastOpened;
  private static volatile int status;
  private static volatile boolean blocked;

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

  /** Opening protocol used only by the corrupt party; honest parties run the original. */
  private static final class TamperedOutputToAllProtocol<PlainT extends CompUInt<?, ?, PlainT>>
      extends Spdz2kNativeProtocol<BigInteger, PlainT> implements RequiresMacCheck {

    private final DRes<SInt> share;
    private final PlainT delta;
    private BigInteger opened;
    private Spdz2kSInt<PlainT> tampered;

    TamperedOutputToAllProtocol(DRes<SInt> share, PlainT delta) {
      this.share = share;
      this.delta = delta;
    }

    @Override
    public EvaluationStatus evaluate(
        int round, Spdz2kResourcePool<PlainT> resourcePool, Network network) {
      OpenedValueStore<Spdz2kSInt<PlainT>, PlainT> openedValueStore =
          resourcePool.getOpenedValueStore();
      if (round == 0) {
        Spdz2kSInt<PlainT> authenticatedElement = (Spdz2kSInt<PlainT>) share.out();
        tampered = new Spdz2kSInt<>(
            authenticatedElement.getShare().add(delta), authenticatedElement.getMacShare());
        network.sendToAll(tampered.getShare().getLeastSignificant().toByteArray());
        return EvaluationStatus.HAS_MORE_ROUNDS;
      } else {
        ByteSerializer<PlainT> serializer = resourcePool.getFactory().getSerializer();
        List<PlainT> shares = serializer.deserializeList(network.receiveFromAll());
        PlainT recombined = UInt.sum(shares);
        openedValueStore.pushOpenedValue(tampered, recombined);
        this.opened = recombined.getLeastSignificant().toBigInteger();
        return EvaluationStatus.IS_DONE;
      }
    }

    @Override
    public BigInteger out() {
      return opened;
    }
  }

  private static class App
      extends TestThreadFactory<Spdz2kResourcePool<CompUInt128>, ProtocolBuilderNumeric> {

    private final boolean tamper;
    private final boolean control;

    App(boolean tamper, boolean control) {
      this.tamper = tamper;
      this.control = control;
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
                      return seq.par(
                          par -> {
                            List<DRes<BigInteger>> outs = new ArrayList<>();
                            if (tamper && par.getBasicNumericContext().getMyId() == 2) {
                              List<BigInteger> coeffs = coefficients(4);
                              // Kernel vector for the last two openings: e1 = r2, e2 = -r1.
                              BigInteger e1 = coeffs.get(3);
                              BigInteger e2 = MOD.subtract(coeffs.get(2));
                              if (!control && (coeffs.get(2).signum() == 0
                                  || coeffs.get(3).signum() == 0)) {
                                throw new IllegalStateException("zero coefficient draw");
                              }
                              if (control) {
                                e1 = BigInteger.ONE;
                                e2 = BigInteger.ZERO;
                              }
                              CompUIntFactory<CompUInt128> factory = new CompUInt128Factory();
                              // The multiply protocol opens two intermediate values first, so the two output
                              // openings are positions 2 and 3 of the four-opening batch.
                              outs.add(par.append(new TamperedOutputToAllProtocol<>(
                                  sum, factory.createElement(e1))));
                              outs.add(par.append(new TamperedOutputToAllProtocol<>(
                                  product, factory.createElement(e2))));
                              status = 1;
                            } else {
                              outs.add(par.numeric().open(sum));
                              outs.add(par.numeric().open(product));
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

  private void run(boolean tamper, boolean control) {
    run(tamper, control, 3);
  }

  private void run(boolean tamper, boolean control, int parties) {
    lastOpened = null;
    status = 0;
    blocked = false;
    System.out.println("MSGLVL_PARTIES " + parties);
    try {
      runTest(new App(tamper, control), EvaluationStrategy.SEQUENTIAL_BATCHED, parties);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      String tag = tamper ? (control ? "MSGLVL_CONTROL" : "MSGLVL_TAMPER") : "MSGLVL_HONEST";
      if (c instanceof dk.alexandra.fresco.framework.MaliciousException) {
        blocked = true;
        System.out.println(tag + "_RESULT blocked");
        return;
      }
      System.out.println(tag + "_RESULT error " + c.getClass().getSimpleName());
      return;
    }
    String tag = tamper ? (control ? "MSGLVL_CONTROL" : "MSGLVL_TAMPER") : "MSGLVL_HONEST";
    System.out.println(tag + "_RESULT status=" + status + " opened=" + lastOpened);
  }

  @Test
  public void honestComputation() {
    run(false, false);
    boolean ok = lastOpened != null
        && lastOpened.equals(Arrays.asList(BigInteger.valueOf(50), BigInteger.valueOf(600)));
    System.out.println("MSGLVL_HONEST_OK " + ok);
    if (!ok) {
      throw new AssertionError("honest output wrong: " + lastOpened);
    }
  }

  @Test
  public void messageLevelTamperAccepted() {
    run(true, false);
    boolean changed = lastOpened != null && lastOpened.size() == 2
        && !lastOpened.get(0).equals(BigInteger.valueOf(50))
        && !lastOpened.get(1).equals(BigInteger.valueOf(600));
    System.out.println("MSGLVL_TAMPER_OK " + (status == 1 && changed));
    if (!(status == 1 && changed)) {
      throw new AssertionError("message-level tamper not observed: status=" + status
          + " opened=" + lastOpened);
    }
  }

  @Test
  public void messageLevelTwoParties() {
    run(true, false, 2);
    boolean changed = lastOpened != null && lastOpened.size() == 2
        && !lastOpened.get(0).equals(BigInteger.valueOf(50))
        && !lastOpened.get(1).equals(BigInteger.valueOf(600));
    System.out.println("MSGLVL_2P_TAMPER_OK " + (status == 1 && changed));
    if (!(status == 1 && changed)) {
      throw new AssertionError("2-party message-level tamper not observed: status=" + status
          + " opened=" + lastOpened);
    }
  }

  @Test
  public void messageLevelFourParties() {
    run(true, false, 4);
    boolean changed = lastOpened != null && lastOpened.size() == 2
        && !lastOpened.get(0).equals(BigInteger.valueOf(50))
        && !lastOpened.get(1).equals(BigInteger.valueOf(600));
    System.out.println("MSGLVL_4P_TAMPER_OK " + (status == 1 && changed));
    if (!(status == 1 && changed)) {
      throw new AssertionError("4-party message-level tamper not observed: status=" + status
          + " opened=" + lastOpened);
    }
  }

  @Test
  public void messageLevelControlBlocked() {
    run(true, true);
    System.out.println("MSGLVL_CONTROL_OK " + blocked);
    if (!blocked) {
      throw new AssertionError("non-kernel control was not blocked");
    }
  }
}
