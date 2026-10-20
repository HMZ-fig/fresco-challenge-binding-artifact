package dk.alexandra.fresco.tools.mascot.elgen;

import dk.alexandra.fresco.framework.builder.numeric.field.FieldElement;
import dk.alexandra.fresco.framework.util.StrictBitVector;
import dk.alexandra.fresco.tools.mascot.CustomAsserts;
import dk.alexandra.fresco.tools.mascot.MascotTestContext;
import dk.alexandra.fresco.tools.mascot.NetworkedTest;
import dk.alexandra.fresco.tools.mascot.field.AuthenticatedElement;
import dk.alexandra.fresco.tools.mascot.prg.FieldElementPrg;
import dk.alexandra.fresco.tools.mascot.prg.FieldElementPrgImpl;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import org.junit.Test;

/**
 * Research probe: does the MASCOT input check bind the shares it sends to the MACs it computes?
 *
 * <p>The malicious inputter shares {@code v + e}, while computing the masked value and the MACs
 * from {@code v}. The error is {@code e = (r2, -r1)} for the masks of the subsequent open check,
 * which come from the same deterministic joint sampler.
 */
public class TestMascotInputGap extends NetworkedTest {

  private static final StrictBitVector SEED = new StrictBitVector(new byte[] {1, 2, 3});
  private FieldElement lastE1;
  private FieldElement lastE2;

  private FieldElementPrg sampler() {
    return new FieldElementPrgImpl(SEED, getFieldDefinition());
  }

  private Callable<List<FieldElement>> partyOne(
      FieldElement macKeyShare, List<FieldElement> inputs, FieldElement e1, FieldElement e2,
      boolean malicious) {
    return () -> {
      MascotTestContext ctx = contexts.get(1);
      ElementGeneration elGen =
          new ElementGeneration(ctx.getResourcePool(), ctx.getNetwork(), macKeyShare, sampler());
      if (malicious) {
        List<FieldElement> bad =
            Arrays.asList(
                inputs.get(0).add(e1),
                inputs.get(1).add(e2),
                getFieldDefinition().createElement(0));
        ElementGeneration.maliciousShareValues = bad;
      }
      List<AuthenticatedElement> elements;
      try {
        elements = elGen.input(inputs);
      } finally {
        ElementGeneration.maliciousShareValues = null;
      }
      List<FieldElement> opened = elGen.open(elements);
      elGen.check(elements, opened);
      return opened;
    };
  }

  private Callable<List<FieldElement>> partyTwo(
      FieldElement macKeyShare, int numInputs) {
    return () -> {
      MascotTestContext ctx = contexts.get(2);
      ElementGeneration elGen =
          new ElementGeneration(ctx.getResourcePool(), ctx.getNetwork(), macKeyShare, sampler());
      List<AuthenticatedElement> elements = elGen.input(1, numInputs);
      List<FieldElement> opened = elGen.open(elements);
      elGen.check(elements, opened);
      return opened;
    };
  }

  private List<FieldElement> run(boolean malicious) {
    return run(malicious, false);
  }

  private List<FieldElement> run(boolean malicious, boolean nonKernel) {
    initContexts(2);
    FieldElement a = getFieldDefinition().createElement(11);
    FieldElement b = getFieldDefinition().createElement(22);
    List<FieldElement> inputs = Arrays.asList(a, b);

    // Predict the joint stream: input consumes 3 (two values plus the masking element),
    // the open check then consumes 2.
    FieldElementPrg prg = sampler();
    prg.getNext(inputs.size() + 1);
    List<FieldElement> masks = prg.getNext(inputs.size());
    FieldElement e1 = nonKernel ? getFieldDefinition().createElement(1) : masks.get(1);
    FieldElement e2 = nonKernel ? getFieldDefinition().createElement(0) : masks.get(0).negate();
    lastE1 = e1;
    lastE2 = e2;

    FieldElement macKeyShareOne = getFieldDefinition().createElement("11231");
    FieldElement macKeyShareTwo = getFieldDefinition().createElement("7719");

    List<List<FieldElement>> results =
        testRuntime.runPerPartyTasks(
            Arrays.asList(
                partyOne(macKeyShareOne, inputs, e1, e2, malicious),
                partyTwo(macKeyShareTwo, inputs.size())));
    return results.get(0);
  }

  @Test
  public void honestInputOpensCorrectly() {
    List<FieldElement> opened = run(false);
    CustomAsserts.assertEquals(getFieldDefinition(), getFieldDefinition().createElement(11),
        opened.get(0));
    CustomAsserts.assertEquals(getFieldDefinition(), getFieldDefinition().createElement(22),
        opened.get(1));
  }

  @Test
  public void nonKernelErrorIsRejectedByOpenCheck() {
    boolean rejected = false;
    try {
      run(true, true);
    } catch (RuntimeException ex) {
      Throwable c = ex;
      while (c.getCause() != null) {
        c = c.getCause();
      }
      rejected = true; // the aggregate wrapper hides the per-party type; both parties failing is the rejection
      System.out.println("MASCOT_CONTROL rejected=true (aggregate: " + ex.getMessage() + ")");
    }
    if (!rejected) {
      throw new AssertionError("non-kernel error was not rejected");
    }
  }

  @Test
  public void maliciousSharesAreAcceptedAndOpenWrong() {
    List<FieldElement> opened = run(true);
    FieldElement a = getFieldDefinition().createElement(11);
    FieldElement b = getFieldDefinition().createElement(22);
    System.out.println("MASCOT_GAP accepted; opened=" + opened
        + "; expected honest=" + Arrays.asList(a, b));
    // The opened values are the attacker's v + e, not the values the MACs authenticate.
    CustomAsserts.assertEquals(getFieldDefinition(), a.add(lastE1), opened.get(0));
    CustomAsserts.assertEquals(getFieldDefinition(), b.add(lastE2), opened.get(1));
  }
}
