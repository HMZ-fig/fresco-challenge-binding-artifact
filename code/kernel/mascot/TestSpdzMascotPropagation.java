package dk.alexandra.fresco.suite.spdz;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.builder.numeric.field.FieldElement;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.suite.spdz.configuration.PreprocessingStrategy;
import dk.alexandra.fresco.tools.mascot.elgen.ElementGeneration;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

/**
 * Research probe: does an inconsistency injected into MASCOT preprocessing abort the SPDZ
 * online phase, or produce a silently wrong opening?
 */
public class TestSpdzMascotPropagation extends AbstractSpdzTest {

  private static volatile List<BigInteger> lastOpened;

  private static class InputOpen
      extends TestThreadFactory<SpdzResourcePool, ProtocolBuilderNumeric> {
    @Override
    public TestThread<SpdzResourcePool, ProtocolBuilderNumeric> next() {
      return new TestThread<SpdzResourcePool, ProtocolBuilderNumeric>() {
        @Override
        public void test() {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app =
              producer -> {
                Numeric numeric = producer.numeric();
                DRes<SInt> x = numeric.input(BigInteger.valueOf(5), 1);
                return producer.seq(
                    seq -> {
                      DRes<BigInteger> open = seq.numeric().open(x);
                      return () -> {
                        List<BigInteger> out = Collections.singletonList(open.out());
                        lastOpened = out;
                        return out;
                      };
                    });
              };
          runApplication(app);
        }
      };
    }
  }

  @Test
  public void honestRunOpensCorrectly() {
    lastOpened = null;
    runTest(new InputOpen(), PreprocessingStrategy.MASCOT, 2);
    if (lastOpened == null || !lastOpened.get(0).equals(BigInteger.valueOf(5))) {
      throw new AssertionError("honest run opened " + lastOpened);
    }
    System.out.println("SPDZ_PROP honest opened=" + lastOpened);
  }

  @Test
  public void corruptMascotInput() {
    ElementGeneration.maliciousPartyId = 1;
    ElementGeneration.maliciousShareTransform =
        values -> {
          List<FieldElement> out = new ArrayList<>(values);
          if (out.size() >= 2) {
            out.set(0, out.get(0).add(out.get(0)));
            out.set(1, out.get(1).add(out.get(1)));
          }
          return out;
        };
    boolean aborted = false;
    String cause = "";
    try {
      runTest(new InputOpen(), PreprocessingStrategy.MASCOT, 2);
    } catch (RuntimeException ex) {
      aborted = true;
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      cause = c.getClass().getSimpleName() + ": " + c.getMessage();
    } finally {
      ElementGeneration.maliciousShareTransform = null;
      ElementGeneration.maliciousPartyId = null;
    }
    System.out.println("SPDZ_PROP aborted=" + aborted + " cause=" + cause);
    if (!aborted) {
      throw new AssertionError("expected the online check to abort");
    }
  }
}
