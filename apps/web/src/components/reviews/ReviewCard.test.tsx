import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  PolicyRegistrySection,
  forgetPolicyRegistry,
  loadRegistry,
  policyRegistryGeneration,
  retryPolicyRegistry,
  ruleForHit,
  ruleThatThrew,
  subscribeToPolicyRegistry,
  type RegistryState,
} from "./ReviewCard";
import type { PolicyRegistryView, PolicyRuleView } from "../../api";
import type { RuleHit } from "../../types";

/**
 * The shape `/api/policy/rules` returns, copied from what the route actually produced rather than
 * invented. The ids and hit ids below are the real ones, including the two that matter here: a rule
 * whose hits are reported under a different name (`protected-identity`), and a rule that appends
 * what it found to its id (`security-regression:`).
 */
function rule(over: Partial<PolicyRuleView> & { id: string; position: number }): PolicyRuleView {
  return {
    decisions: ["review"],
    hitIds: [over.id],
    summary: "A rule that judges something and says one line about it here.",
    ...over,
  };
}

const RULES: PolicyRuleView[] = [
  rule({
    id: "protected-identity",
    position: 1,
    decisions: ["discard"],
    hitIds: ["protected-asset-delete", "protected-asset-write"],
  }),
  rule({
    id: "exec-surface",
    position: 4,
    decisions: ["discard", "review"],
    hitIds: ["execution-surface-write", "execution-surface-review"],
  }),
  rule({ id: "security-regression", position: 12, hitIds: ["security-regression:"] }),
  rule({ id: "cross-effect-composition", position: 15, hitIds: ["composed-remote-to-exec"] }),
];

const REGISTRY: PolicyRegistryView = {
  count: RULES.length,
  rules: RULES,
  notes: {
    noShortCircuit: true,
    reportsFiredNotEvaluated: true,
    authorizationAhead: {
      hitIdPrefix: "capability-",
      decisions: ["review"],
      stopsAtFirstFailure: true,
    },
    ruleErrorHitId: "policy-rule-error",
  },
};

const ready: RegistryState = { status: "ready", registry: REGISTRY };
const html = (state: RegistryState, hits: RuleHit[]): string =>
  renderToStaticMarkup(<PolicyRegistrySection hits={hits} state={state} onRetry={() => {}} />);

/** the row for one rule, so an assertion is about that rule and not about the whole page */
function rowOf(markup: string, id: string): string {
  const rows = markup.split("<li").map((chunk) => "<li" + chunk);
  return rows.find((row) => row.includes(">" + id + "<") || row.includes(". " + id + "<")) ?? "";
}

describe("mapping a recorded hit back to the rule that produced it", () => {
  it("matches a rule whose hits are reported under a different name", () => {
    const hit: RuleHit = { rule: "protected-asset-delete", decision: "discard" };
    expect(ruleForHit(hit, RULES)?.id).toBe("protected-identity");
  });

  it("matches every declared id of every rule, not only the first of each", () => {
    // sweeping the axis: the one-point version of this test passed while the loop looked at
    // hitIds[0] only, which would have left execution-surface-review unattributed
    for (const declared of RULES) {
      for (const id of declared.hitIds) {
        const probe = id.endsWith(":") ? id + "tls-verification-disabled" : id;
        expect([probe, ruleForHit({ rule: probe, decision: "review" }, RULES)?.id]).toEqual([
          probe,
          declared.id,
        ]);
      }
      expect([declared.id, ruleForHit({ rule: declared.id, decision: "review" }, RULES)?.id]).toEqual([
        declared.id,
        declared.id,
      ]);
    }
  });

  it("refuses to attribute a hit that came from outside the registry", () => {
    expect(ruleForHit({ rule: "capability-path-out-of-scope", decision: "review" }, RULES)).toBeNull();
    expect(ruleForHit({ rule: "policy-rule-error", decision: "review" }, RULES)).toBeNull();
    // and a near miss is not a match: a prefix rule must not swallow an unrelated id
    expect(ruleForHit({ rule: "security-regressions-report", decision: "review" }, RULES)).toBeNull();
    expect(ruleForHit({ rule: "protected-asset", decision: "discard" }, RULES)).toBeNull();
  });
});

describe("the rule set on a held turn", () => {
  const hit: RuleHit = { rule: "protected-asset-delete", decision: "discard", path: "src/.git/HEAD" };

  it("lists every rule the server reported, not only the ones that fired", () => {
    const out = html(ready, [hit]);
    for (const declared of RULES) {
      expect([declared.id, out.includes(declared.id)]).toEqual([declared.id, true]);
      expect([declared.id, out.includes(declared.summary)]).toEqual([declared.id, true]);
    }
    // the apostrophe arrives html-escaped, so the assertion stops before it
    expect(out).toContain("4 rules, 1 named in this turn");
  });

  it("marks the rule the hit came from and leaves the rules that abstained unmarked", () => {
    const out = html(ready, [hit]);
    expect(rowOf(out, "protected-identity")).toContain("hit hit-discard");
    expect(rowOf(out, "protected-identity")).toContain("fired here");
    for (const quiet of ["exec-surface", "security-regression", "cross-effect-composition"]) {
      expect([quiet, rowOf(out, quiet).includes("fired here")]).toEqual([quiet, false]);
      expect([quiet, rowOf(out, quiet).includes('class="hit ')]).toEqual([quiet, false]);
    }
  });

  it("marks a fired rule with the decision it actually returned, not the worst it could return", () => {
    // exec-surface can discard; on this turn it asked for a person, and the row has to say that
    const out = html(ready, [{ rule: "execution-surface-review", decision: "review" }]);
    expect(rowOf(out, "exec-surface")).toContain("hit hit-review");
    expect(rowOf(out, "exec-surface")).not.toContain("hit-discard");
    expect(rowOf(out, "exec-surface")).toContain("asks a human");
  });

  it("says the server reports what fired and not what was evaluated", () => {
    // the sentence that keeps this screen from being a claim the server never made
    const out = html(ready, [hit]);
    expect(out).toContain("records which rules fired, not which rules it evaluated");
    expect(out).toContain("registry");
    // scoped to the list, because the flag is: `noShortCircuit` is about the registry loop and the
    // authorization stage ahead of it does stop at its first failing question
    expect(out).toContain("Nothing in this list short-circuits");
  });

  it("labels a rule nothing named as a capability, not as a verdict on this turn", () => {
    // "would discard or asks a human" as a bare row label, sitting under rows reading "fired here,
    // would discard", read as a statement about the turn in front of you. It is not one.
    const out = html(ready, [hit]);
    const quiet = rowOf(out, "exec-surface");
    expect(quiet).toContain("not named in this turn");
    expect(quiet).toContain("can discard or can ask a human");
    expect(quiet).not.toContain("fired here");
    // and the marked row still says what it returned, in the other voice
    expect(rowOf(out, "protected-identity")).toContain("fired here, would discard");
    expect(rowOf(out, "protected-identity")).not.toContain("can discard");
  });

  it("names a hit from outside the registry as such instead of forcing it onto a rule", () => {
    const out = html(ready, [hit, { rule: "capability-path-out-of-scope", decision: "review" }]);
    expect(out).toContain("capability-path-out-of-scope");
    expect(out).toContain("outside that registry");
    expect(out).toContain("checked ahead of the rule set");
    // the count in the summary counts registry rules, so the extra hit does not inflate it
    // the apostrophe arrives html-escaped, so the assertion stops before it
    expect(out).toContain("4 rules, 1 named in this turn");
    expect(out).toContain("1 reported from outside the registry");
  });

  it("does not draw the outside-the-registry section when there is nothing in it", () => {
    expect(html(ready, [hit])).not.toContain("outside that registry");
  });
});

/**
 * The paragraph over the outside-the-registry list used to name two causes, a capability grant and
 * a rule that threw, as the explanation for every hit in it. A hit a registry rule reported under an
 * id it does not declare is neither, and got printed under whichever of the two the reader took
 * first. Every hit now gets the sentence that matches the hit in hand, and a hit the panel cannot
 * place gets a sentence that says so instead of a cause.
 */
describe("a hit the registry list cannot place", () => {
  const capability: RuleHit = {
    rule: "capability-path-out-of-scope",
    decision: "review",
    path: "src/a.ts",
    detail: "Workspace path is outside the operator-issued grant",
  };
  const threw: RuleHit = {
    rule: "policy-rule-error",
    decision: "review",
    detail: "exec-surface: Cannot read properties of undefined",
  };
  // exactly the shape that made this reachable: an id `protected-identity` can report but does not
  // declare, so ruleForHit returns null and no published fact explains where it came from
  const undeclared: RuleHit = { rule: "protected-asset-escalated", decision: "discard" };

  it("gives the capability sentence only to a hit under the published prefix", () => {
    const out = html(ready, [capability]);
    expect(out).toContain("checked ahead of the rule set");
    expect(out).not.toContain("A rule threw");
    expect(out).not.toContain("does not publish");
  });

  it("gives the thrown-rule sentence only to a hit under the published error id", () => {
    const out = html(ready, [threw]);
    expect(out).toContain("A rule threw");
    expect(out).not.toContain("checked ahead of the rule set");
    expect(out).not.toContain("does not publish");
  });

  it("claims no cause at all for a hit reported under an id the registry does not publish", () => {
    const out = html(ready, [undeclared]);
    expect(out).toContain("Reported under an id this registry does not publish");
    expect(out).toContain("protected-asset-escalated");
    // the two causes the old paragraph asserted over every hit, neither of which is this one
    expect(out).not.toContain("checked ahead of the rule set");
    expect(out).not.toContain("A rule threw");
    // and the headline does not read as though nothing at all was reported
    expect(out).toContain("1 reported from outside the registry");
  });

  it("keeps the three groups apart when all three arrive on one turn", () => {
    const out = html(ready, [capability, threw, undeclared]);
    expect(out).toContain("checked ahead of the rule set");
    expect(out).toContain("A rule threw");
    expect(out).toContain("Reported under an id this registry does not publish");
    expect(out).toContain("3 reported from outside the registry");
  });

  it("renders the detail, which for a thrown rule is the only thing naming the rule", () => {
    const out = html(ready, [capability, threw]);
    expect(out).toContain("Workspace path is outside the operator-issued grant");
    expect(out).toContain("Cannot read properties of undefined");
    expect(out).toContain("src/a.ts");
  });

  it("marks the row of the rule that threw, so it does not read as a rule nothing happened to", () => {
    const out = html(ready, [threw]);
    expect(rowOf(out, "exec-surface")).toContain("threw here, reported as policy-rule-error");
    expect(rowOf(out, "exec-surface")).toContain('class="hit ');
    expect(rowOf(out, "exec-surface")).not.toContain("not named in this turn");
    // every other row is untouched by it
    for (const quiet of ["protected-identity", "security-regression", "cross-effect-composition"]) {
      expect([quiet, rowOf(out, quiet).includes("threw here")]).toEqual([quiet, false]);
    }
  });

  it("marks nothing when the detail does not name a rule the server published", () => {
    // a guess would put the mark on whichever row the parse happened to land on
    for (const detail of [undefined, "", "no colon here", "not-a-rule: boom", ": boom"]) {
      expect([detail, ruleThatThrew({ rule: "policy-rule-error", decision: "review", detail }, RULES)]).toEqual([
        detail,
        null,
      ]);
      const out = html(ready, [{ rule: "policy-rule-error", decision: "review", detail }]);
      expect([detail, out.includes("threw here")]).toEqual([detail, false]);
    }
    expect(ruleThatThrew({ rule: "policy-rule-error", decision: "review", detail: "exec-surface: boom" }, RULES)?.id)
      .toBe("exec-surface");
  });

  it("stays in the unplaced group across every id shape that is neither cause", () => {
    // the axis rather than the one id: a near-miss on the prefix, a near-miss on the error id, and
    // an id from a rule module that simply does not declare it
    const strangers = [
      "protected-asset-escalated",
      "capabilities-gone",
      "capabilit-path",
      "policy-rule-errors",
      "grant-path-out-of-scope",
      "",
    ];
    for (const id of strangers) {
      const out = html(ready, [{ rule: id, decision: "review" }]);
      expect([id, out.includes("Reported under an id this registry does not publish")]).toEqual([id, true]);
      expect([id, out.includes("checked ahead of the rule set")]).toEqual([id, false]);
      expect([id, out.includes("A rule threw")]).toEqual([id, false]);
    }
  });
});

describe("a rule set the panel could not read", () => {
  const failed: RegistryState = { status: "error", message: "Authentication required" };

  it("says it could not be read, and says whose failure that is", () => {
    const out = html(failed, [{ rule: "protected-asset-delete", decision: "discard" }]);
    expect(out).toContain("could not be read");
    expect(out).toContain("Authentication required");
    expect(out).toContain("not a report that no rules ran");
    expect(out).toContain("Try reading the rule set again");
  });

  it("does not render a confident empty list or a rule count it does not have", () => {
    const out = html(failed, []);
    expect(out).not.toContain("<li");
    expect(out).not.toContain("0 rules");
    expect(out).not.toContain("named in this turn");
  });

  it("is open by default, so a failure is not hidden behind a collapsed summary", () => {
    expect(html(failed, [])).toContain("<details");
    expect(html(failed, [])).toContain("open");
  });
});

describe("a rule set the panel has not read yet", () => {
  it("says it is reading rather than claiming a count", () => {
    const out = html({ status: "loading" }, []);
    expect(out).toContain("reading the rule set");
    expect(out).not.toContain("<li");
    expect(out).not.toContain("0 rules");
  });
});

/**
 * The two sentences the registry cache made and nothing checked: "one fetch per page rather than
 * one per card" and "a failure is not cached, so Retry really retries". Both rested on reading, and
 * so did the third one, which turned out to be false: retry kept its counter in each card's own
 * `useState`, so on a page with ten held turns one click refetched once and the other nine cards
 * went on showing "could not be read".
 */
describe("reading the rule set once for a page instead of once per card", () => {
  it("asks the server once however many cards ask, and hands them all the same answer", async () => {
    forgetPolicyRegistry();
    let calls = 0;
    const fetcher = async (): Promise<PolicyRegistryView> => {
      calls += 1;
      return REGISTRY;
    };
    const answers = await Promise.all(Array.from({ length: 10 }, () => loadRegistry(fetcher)));
    expect(calls).toBe(1);
    for (const answer of answers) expect(answer).toBe(REGISTRY);
    // and a card that mounts later still gets it without a second request
    expect(await loadRegistry(fetcher)).toBe(REGISTRY);
    expect(calls).toBe(1);
    forgetPolicyRegistry();
  });

  it("does not cache a failure, so the next read really goes back to the server", async () => {
    forgetPolicyRegistry();
    let calls = 0;
    const failing = async (): Promise<PolicyRegistryView> => {
      calls += 1;
      throw new Error("Authentication required");
    };
    await expect(loadRegistry(failing)).rejects.toThrow("Authentication required");
    await expect(loadRegistry(failing)).rejects.toThrow("Authentication required");
    expect(calls).toBe(2);
    // and once it succeeds the failure is not what is remembered
    const working = async (): Promise<PolicyRegistryView> => REGISTRY;
    expect(await loadRegistry(working)).toBe(REGISTRY);
    forgetPolicyRegistry();
  });

  it("tells every card to read again, not only the one whose Retry was clicked", () => {
    const woken: string[] = [];
    const unsubscribes = ["card-1", "card-2", "card-3"].map((card) =>
      subscribeToPolicyRegistry(() => woken.push(card)),
    );
    const before = policyRegistryGeneration();

    retryPolicyRegistry();

    expect(woken).toEqual(["card-1", "card-2", "card-3"]);
    expect(policyRegistryGeneration()).toBe(before + 1);
    for (const stop of unsubscribes) stop();
  });

  it("drops the cached answer when Retry is pressed, so the refetch is a real one", async () => {
    forgetPolicyRegistry();
    let calls = 0;
    const fetcher = async (): Promise<PolicyRegistryView> => {
      calls += 1;
      return REGISTRY;
    };
    await loadRegistry(fetcher);
    await loadRegistry(fetcher);
    expect(calls).toBe(1);

    retryPolicyRegistry();
    await loadRegistry(fetcher);
    expect(calls).toBe(2);
    forgetPolicyRegistry();
  });

  it("stops waking a card that unsubscribed, so an unmounted card cannot set state", () => {
    const woken: string[] = [];
    const stopFirst = subscribeToPolicyRegistry(() => woken.push("gone"));
    const stopSecond = subscribeToPolicyRegistry(() => woken.push("here"));
    stopFirst();

    retryPolicyRegistry();

    expect(woken).toEqual(["here"]);
    stopSecond();
  });
});
