import { useCallback, useEffect, useState } from "react";
import { ProposedChanges } from "./ProposedChanges";
import { Spinner } from "../ui/Spinner";
import { shortHash, shortPath } from "../../lib/format";
import { api, type PolicyRegistryView, type PolicyRuleView } from "../../api";
import type { Review, RuleHit } from "../../types";

/**
 * What the panel knows about the rule set. A registry it could not read is a state of its own and
 * says so: rendering an empty list instead would tell the operator that no rules exist, which is
 * the confident empty state this panel already has too much of.
 */
export type RegistryState =
  | { status: "loading" }
  | { status: "ready"; registry: PolicyRegistryView }
  | { status: "error"; message: string };

/**
 * One fetch per page rather than one per card. The registry is a property of the server, not of a
 * held turn, so every card asks the same question and there is no reason to ask it ten times. A
 * failure is not cached: clearing the slot is what lets Retry actually retry.
 *
 * Retry is page-wide, and it has to be. The first version kept the attempt counter in each card's
 * own `useState`, so on a page with ten held turns clicking Retry on one card refetched once and
 * the other nine went on rendering "Policy registry: could not be read" until something else
 * happened to re-render them. The generation counter and the listener set below are what turn one
 * click into one refetch that every card sees. Both are module state on purpose: the cache they
 * guard is module state too, and a per-card copy of either reintroduces the same split.
 */
let registryRequest: Promise<PolicyRegistryView> | null = null;
let registryGeneration = 0;
const registryListeners = new Set<() => void>();

export function loadRegistry(
  fetcher: () => Promise<PolicyRegistryView> = api.policyRules,
): Promise<PolicyRegistryView> {
  if (!registryRequest) {
    registryRequest = fetcher().catch((reason: unknown) => {
      registryRequest = null;
      throw reason;
    });
  }
  return registryRequest;
}

/** Exported for tests: drops the cached registry so the next read goes back to the server. */
export function forgetPolicyRegistry(): void {
  registryRequest = null;
}

/** Which read every card is on. A card that is behind this number has an answer to throw away. */
export function policyRegistryGeneration(): number {
  return registryGeneration;
}

export function subscribeToPolicyRegistry(listener: () => void): () => void {
  registryListeners.add(listener);
  return () => {
    registryListeners.delete(listener);
  };
}

/** Drops the cached answer and tells EVERY card to ask again, not only the one that was clicked. */
export function retryPolicyRegistry(): void {
  forgetPolicyRegistry();
  registryGeneration += 1;
  for (const listener of [...registryListeners]) listener();
}

export function usePolicyRegistry(): { state: RegistryState; retry: () => void } {
  const [state, setState] = useState<RegistryState>({ status: "loading" });
  const [attempt, setAttempt] = useState(registryGeneration);

  useEffect(() => subscribeToPolicyRegistry(() => setAttempt(policyRegistryGeneration())), []);

  useEffect(() => {
    let live = true;
    setState({ status: "loading" });
    void loadRegistry().then(
      (registry) => live && setState({ status: "ready", registry }),
      (reason: unknown) =>
        live &&
        setState({
          status: "error",
          message: reason instanceof Error ? reason.message : String(reason),
        }),
    );
    return () => {
      live = false;
    };
  }, [attempt]);

  const retry = useCallback(() => retryPolicyRegistry(), []);

  return { state, retry };
}

/**
 * The rule a recorded hit came from, or null.
 *
 * A rule does not always report under its own name: `protected-identity` reports
 * `protected-asset-delete`, so the server publishes the ids each rule can report under and this
 * matches against those. An id ending in ":" is a prefix, which is how `security-regression:`
 * carries the idiom it found. A hit that matches nothing came from outside the registry, and the
 * honest thing to do with it is say so rather than force it onto a row.
 */
export function ruleForHit(hit: RuleHit, rules: PolicyRuleView[]): PolicyRuleView | null {
  for (const rule of rules) {
    if (rule.id === hit.rule) return rule;
    for (const id of rule.hitIds) {
      if (id.endsWith(":") ? hit.rule.startsWith(id) : id === hit.rule) return rule;
    }
  }
  return null;
}

const decisionWord = (decision: string): string =>
  decision === "discard" ? "would discard" : "asks a human";

/**
 * What a rule CAN return, said as a capability rather than as a verdict on this turn.
 *
 * The bare "would discard or asks a human" this replaced sat directly under rows reading
 * "fired here, would discard", where it read as a statement about the turn in front of you. It is
 * not one, and the panel cannot make it one: the server records the rules that fired, so a rule
 * this card leaves unmarked was not NAMED in this turn's hits, which is a weaker claim than "did
 * not run" and weaker again than "abstained". The label says exactly that much and no more.
 */
const capabilityWord = (decision: string): string =>
  decision === "discard" ? "can discard" : "can ask a human";

/**
 * The rule a `policy-rule-error` hit is about, out of the detail the policy wrote.
 *
 * `shadow-policy.ts` builds that detail as `${rule.name}: ${message}`, so the name is everything
 * before the first colon. It is only trusted when it matches a rule the server published: a detail
 * in any other shape leaves the row unmarked rather than marking whichever row a guess landed on.
 */
export function ruleThatThrew(hit: RuleHit, rules: PolicyRuleView[]): PolicyRuleView | null {
  const named = hit.detail?.split(":", 1)[0]?.trim() ?? "";
  if (!named) return null;
  return rules.find((rule) => rule.id === named) ?? null;
}

/**
 * Every rule in the set, with the ones this turn's hits name marked.
 *
 * This is the no-short-circuit property made visible, and it is a claim about the server, so it is
 * built only out of what the server said: the registry comes from `/api/policy/rules` and the
 * marks come from the hits recorded on this turn. It is NOT a per-turn record of what ran, because
 * the server does not keep one, and the paragraph below says that in the panel rather than only
 * here. Nothing on this screen is assembled from a list of rule names held on the client.
 */
export function PolicyRegistrySection({
  hits,
  state,
  onRetry,
}: {
  hits: RuleHit[];
  state: RegistryState;
  onRetry: () => void;
}) {
  if (state.status === "loading") {
    return (
      <details className="registry-section">
        <summary>Policy registry: reading the rule set</summary>
        <p>Asking the server which rules are registered.</p>
      </details>
    );
  }

  if (state.status === "error") {
    return (
      <details className="registry-section" open>
        <summary>Policy registry: could not be read</summary>
        <p>
          The rule set could not be read from the server: {state.message}. That is this panel failing
          to ask, not a report that no rules ran. The hits above are what the boundary recorded for
          this turn and are unaffected.
        </p>
        <button className="button button-ghost" onClick={onRetry}>
          Try reading the rule set again
        </button>
      </details>
    );
  }

  const { registry } = state;
  const { hitIdPrefix, stopsAtFirstFailure } = registry.notes.authorizationAhead;

  // rule id -> the decision it actually returned here, worst first. Marking a row by what the rule
  // CAN return would paint a rule that asked for a person as one that would have discarded.
  const firedRules = new Map<string, RuleHit["decision"]>();
  // rule id -> the decision of the policy-rule-error hit that names it. A rule that threw pushed no
  // hits of its own, so without this its row renders exactly like a rule nothing happened to.
  const threwRules = new Map<string, RuleHit["decision"]>();

  // Each hit gets the sentence that matches the hit in hand, and no hit gets a cause the panel
  // cannot check. The single-paragraph version named two causes over the whole list, so a hit a
  // registry rule reported under an id it does not declare was printed under "a capability grant"
  // or "a rule that threw" with no evidence for either.
  const fromAuthorization: RuleHit[] = [];
  const fromThrownRule: RuleHit[] = [];
  const unattributed: RuleHit[] = [];
  for (const hit of hits) {
    const rule = ruleForHit(hit, registry.rules);
    if (rule) {
      if (firedRules.get(rule.id) !== "discard") firedRules.set(rule.id, hit.decision);
      continue;
    }
    if (hit.rule === registry.notes.ruleErrorHitId) {
      fromThrownRule.push(hit);
      const threw = ruleThatThrew(hit, registry.rules);
      if (threw) threwRules.set(threw.id, hit.decision);
      continue;
    }
    if (hitIdPrefix.length > 0 && hit.rule.startsWith(hitIdPrefix)) {
      fromAuthorization.push(hit);
      continue;
    }
    unattributed.push(hit);
  }
  const outsideCount = fromAuthorization.length + fromThrownRule.length + unattributed.length;

  const outsideList = (list: RuleHit[]) => (
    <ul className="hit-list">
      {list.map((hit, index) => (
        <li key={hit.rule + index} className={"hit hit-" + hit.decision}>
          <span className="hit-rule">{hit.rule}</span>
          <span className="hit-decision">{decisionWord(hit.decision)}</span>
          {hit.path && <code className="hit-path">{hit.path}</code>}
          {hit.detail && <span className="hit-detail">{hit.detail}</span>}
        </li>
      ))}
    </ul>
  );

  return (
    <details className="registry-section">
      <summary>
        Policy registry: {registry.count} rules, {firedRules.size} named in this turn's hits
        {outsideCount > 0 ? ", " + outsideCount + " reported from outside the registry" : ""}
      </summary>

      <p>
        Every rule below runs on every turn. Nothing in this list short-circuits, so a rule that asks
        for a person cannot hide a rule that would discard: the policy collects every hit and the
        worst decision wins.
      </p>
      <p>
        The server records which rules fired, not which rules it evaluated, so this is the registry
        as the server reports it now rather than a record of this turn. Marked rules are the ones a
        hit on this turn was reported under.
      </p>

      <ul className="hit-list">
        {registry.rules.map((rule) => {
          const fired = firedRules.get(rule.id);
          const threw = threwRules.get(rule.id);
          const mark = fired ?? threw;
          return (
            <li key={rule.id} className={mark ? "hit hit-" + mark : "registry-rule"}>
              <span className="hit-rule">
                {rule.position}. {rule.id}
              </span>
              <span className="hit-decision">
                {fired
                  ? "fired here, " + decisionWord(fired)
                  : threw
                    ? "threw here, reported as " + registry.notes.ruleErrorHitId
                    : "not named in this turn's hits; " +
                      rule.decisions.map(capabilityWord).join(" or ")}
              </span>
              <span className="hit-detail">{rule.summary}</span>
            </li>
          );
        })}
      </ul>

      {outsideCount > 0 && <p>Reported on this turn from outside that registry.</p>}

      {fromAuthorization.length > 0 && (
        <>
          <p>
            A capability grant is checked ahead of the rule set and reports under{" "}
            <code>{hitIdPrefix}</code>.
            {stopsAtFirstFailure
              ? " That check stops at its first failing question, so it can report fewer reasons than the turn has: widening the grant can make a further set appear."
              : ""}
          </p>
          {outsideList(fromAuthorization)}
        </>
      )}

      {fromThrownRule.length > 0 && (
        <>
          <p>
            A rule threw. The policy caught it, recorded it as{" "}
            <code>{registry.notes.ruleErrorHitId}</code>, and every other rule still ran. Where the
            detail names a rule in the list above, that row is marked as having thrown rather than
            left to read as a rule nothing happened to.
          </p>
          {outsideList(fromThrownRule)}
        </>
      )}

      {unattributed.length > 0 && (
        <>
          <p>
            Reported under an id this registry does not publish. It is not the capability grant and
            it is not a rule that threw, and nothing the server sent says which rule reported it, so
            this panel does not guess.
          </p>
          {outsideList(unattributed)}
        </>
      )}
    </details>
  );
}

/**
 * One held turn. It names the agent, the rule that held it, every rule that fired, the whole rule
 * set that the fired ones came from, and the exact set of changes waiting. Approving sends back the
 * hash of that set, so an approval can only ever apply what the operator was looking at.
 */
export function ReviewCard({
  review,
  agentName,
  busy,
  onApprove,
  onReject,
}: {
  review: Review;
  agentName: string;
  busy: boolean;
  onApprove: (review: Review) => void;
  onReject: (review: Review) => void;
}) {
  const hits = review.hits.length > 0 ? review.hits : [{ rule: review.rule, decision: "review" as const }];
  const { state, retry } = usePolicyRegistry();

  return (
    <article className="review-card">
      <header className="review-head">
        <div className="review-title">
          <span className="eyebrow">Held for review</span>
          <h3>{agentName}</h3>
          <p>
            {review.effectCount} proposed {review.effectCount === 1 ? "change" : "changes"} against{" "}
            <code title={review.workspacePath}>{shortPath(review.workspacePath, 2)}</code>
          </p>
        </div>
        <span className="review-seq" title={review.heldAt ?? "held for review"}>
          {review.heldAt ? new Date(review.heldAt).toLocaleTimeString() : "held"}
        </span>
      </header>

      <ul className="hit-list">
        {hits.map((hit, index) => (
          <li key={hit.rule + index} className={"hit hit-" + hit.decision}>
            <span className="hit-rule">{hit.rule}</span>
            <span className="hit-decision">{hit.decision === "review" ? "asks a human" : "would discard"}</span>
            {hit.path && <code className="hit-path">{hit.path}</code>}
            {hit.detail && <span className="hit-detail">{hit.detail}</span>}
          </li>
        ))}
      </ul>

      <PolicyRegistrySection hits={hits} state={state} onRetry={retry} />

      <ProposedChanges changes={review.effects} truncated={review.truncated} idPrefix={review.runId} />

      <footer className="review-actions">
        <p className="review-hash">
          Approving effect set <code title={review.effectSetHash}>{shortHash(review.effectSetHash)}</code>. If it
          changes before you decide, the approval is refused rather than applied.
        </p>
        <div className="review-buttons">
          <button className="button button-ghost" disabled={busy} onClick={() => onReject(review)}>
            Reject
          </button>
          <button className="button button-primary" disabled={busy} onClick={() => onApprove(review)}>
            {busy ? <Spinner /> : "Approve and commit"}
          </button>
        </div>
      </footer>
    </article>
  );
}
