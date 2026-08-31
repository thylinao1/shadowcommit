import {
  effectiveCapabilityGrant,
  type CapabilityGrantStore,
  type EffectiveCapabilityGrant,
} from "./capability-grants.js";
import type {
  EffectRecord,
  Policy,
  PolicyContext,
  PolicyVerdict,
  RuleHit,
} from "./policy-types.js";

export type CapabilityGrantRule = (
  effects: EffectRecord[],
  context: PolicyContext,
) => Promise<PolicyVerdict | null>;

function safeRelativePath(raw: string): string | null {
  const candidate = raw.normalize("NFC").replaceAll("\\", "/");
  if (!candidate || candidate.startsWith("/") || /^[A-Za-z]:/.test(candidate)) return null;
  const parts = candidate.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) return null;
  return parts.join("/");
}

function resolvedSymlinkTarget(linkPath: string, rawTarget: string): string | null {
  const normalizedLink = safeRelativePath(linkPath);
  const target = rawTarget.normalize("NFC").replaceAll("\\", "/");
  if (
    !normalizedLink ||
    !target ||
    target.startsWith("/") ||
    /^[A-Za-z]:/.test(target) ||
    /[\0\r\n]/.test(target)
  ) {
    return null;
  }
  const resolved = normalizedLink.split("/");
  resolved.pop();
  for (const segment of target.split("/")) {
    if (!segment || segment === ".") continue;
    if (segment === "..") {
      if (resolved.length === 0) return null;
      resolved.pop();
    } else {
      resolved.push(segment);
    }
  }
  return safeRelativePath(resolved.join("/"));
}

function globExpression(glob: string, slashSensitive: boolean): RegExp {
  let expression = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index] ?? "";
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") {
        expression += "(?:.*/)?";
        index += 2;
      } else {
        expression += ".*";
        index += 1;
      }
    } else if (character === "*") {
      expression += slashSensitive ? "[^/]*" : ".*";
    } else if (character === "?") {
      expression += slashSensitive ? "[^/]" : ".";
    } else {
      expression += character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(expression + "$");
}

export function pathMatchesCapability(
  rawPath: string,
  allowedPathGlobs: readonly string[],
  caseInsensitive = false,
): boolean {
  const normalized = safeRelativePath(rawPath);
  if (!normalized) return false;
  const candidate = caseInsensitive ? normalized.toLocaleLowerCase("en-US") : normalized;
  return allowedPathGlobs.some((rawGlob) => {
    const normalizedGlob = rawGlob.normalize("NFC").replaceAll("\\", "/");
    const glob = caseInsensitive ? normalizedGlob.toLocaleLowerCase("en-US") : normalizedGlob;
    return globExpression(glob, true).test(candidate);
  });
}

interface DestinationParts {
  host: string;
  authority: string;
  path: string;
}

function effectDestination(effect: EffectRecord): DestinationParts | null {
  const rawHost = effect.host?.trim().normalize("NFC").toLocaleLowerCase("en-US") ?? "";
  const host = rawHost.endsWith(".") ? rawHost.slice(0, -1) : rawHost;
  if (
    !host ||
    /[\s/@?#]/.test(host) ||
    (effect.port !== undefined &&
      (!Number.isInteger(effect.port) || effect.port < 1 || effect.port > 65_535))
  ) {
    return null;
  }
  const renderedHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const authority = effect.port ? `${renderedHost}:${effect.port}` : renderedHost;
  const rawPath = effect.urlPath || "/";
  if (!rawPath.startsWith("/") || /[\0\r\n]/.test(rawPath)) return null;
  const segments = rawPath.split("/");
  if (segments.some((segment) => segment === ".." || /%(?:2e|2f|5c)/i.test(segment))) return null;
  return { host: renderedHost, authority, path: rawPath };
}

export function destinationMatchesCapability(
  effect: EffectRecord,
  allowedDestinations: readonly string[],
): boolean {
  const destination = effectDestination(effect);
  if (!destination) return false;
  return allowedDestinations.some((rawPattern) => {
    const pattern = rawPattern.normalize("NFC");
    if (pattern === "*") return true;
    const slash = pattern.indexOf("/");
    const authorityPattern = (slash === -1 ? pattern : pattern.slice(0, slash))
      .toLocaleLowerCase("en-US");
    const pathPattern = slash === -1 ? null : pattern.slice(slash);
    const hasExplicitPort = authorityPattern.startsWith("[")
      ? authorityPattern.includes("]:")
      : authorityPattern.includes(":");
    const authorityCandidate = hasExplicitPort ? destination.authority : destination.host;
    if (!globExpression(authorityPattern, false).test(authorityCandidate)) return false;
    return pathPattern === null || globExpression(pathPattern, true).test(destination.path);
  });
}

function review(rule: string, hits: RuleHit[]): PolicyVerdict {
  return { decision: "review", rule, hits };
}

function scopeHits(
  effects: EffectRecord[],
  context: PolicyContext,
  grant: EffectiveCapabilityGrant,
): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const effect of effects) {
    if (effect.kind === "outbound") {
      if (!destinationMatchesCapability(effect, grant.allowedDestinations)) {
        hits.push({
          rule: "capability-destination-out-of-scope",
          decision: "review",
          path: effect.path,
          detail: "Outbound destination is outside the operator-issued grant",
        });
      }
      continue;
    }
    const candidate = context.caseInsensitiveHost && effect.canonicalPath
      ? effect.canonicalPath
      : effect.path;
    if (!pathMatchesCapability(candidate, grant.allowedPathGlobs, context.caseInsensitiveHost)) {
      hits.push({
        rule: "capability-path-out-of-scope",
        decision: "review",
        path: effect.path,
        detail: "Workspace path is outside the operator-issued grant",
      });
    }
    if (effect.kind === "symlink") {
      const target = effect.target
        ? resolvedSymlinkTarget(effect.path, effect.target)
        : null;
      if (
        !target ||
        !pathMatchesCapability(target, grant.allowedPathGlobs, context.caseInsensitiveHost)
      ) {
        hits.push({
          rule: "capability-symlink-target-out-of-scope",
          decision: "review",
          path: effect.path,
          detail: "Symlink target resolves outside the operator-issued path grant",
        });
      }
    }
  }
  return hits;
}

/**
 * Returns null when capability authorization succeeds so the next rule can run. Every failure is
 * a review verdict. This function never reads effect content.
 */
export function createCapabilityGrantRule(store: CapabilityGrantStore): CapabilityGrantRule {
  return async (effects, context) => {
    if (effects.length === 0) return null;
    if (!context.agentId) {
      return review("capability-agent-unidentified", [
        {
          rule: "capability-agent-unidentified",
          decision: "review",
          detail: "Policy context did not identify the Agent principal",
        },
      ]);
    }
    const grant = await effectiveCapabilityGrant(store, context.agentId);
    if (grant.status === "revoked") {
      return review("capability-grant-revoked", [
        {
          rule: "capability-grant-revoked",
          decision: "review",
          detail: `Capability grant revision ${grant.revision} is revoked`,
        },
      ]);
    }
    if (effects.length > grant.budget) {
      return review("capability-budget-exceeded", [
        {
          rule: "capability-budget-exceeded",
          decision: "review",
          detail: `Turn proposed ${effects.length} effects against a budget of ${grant.budget}`,
        },
      ]);
    }
    const hits = scopeHits(effects, context, grant);
    return hits.length ? review(hits[0]?.rule ?? "capability-out-of-scope", hits) : null;
  };
}

function hitList(verdict: PolicyVerdict): RuleHit[] {
  const hits = [...(verdict.hits ?? [])];
  if (
    verdict.decision !== "commit" &&
    !hits.some((hit) => hit.rule === verdict.rule && hit.decision === verdict.decision)
  ) {
    hits.unshift({ rule: verdict.rule, decision: verdict.decision });
  }
  return hits;
}

function stricterVerdict(
  authorization: PolicyVerdict | null,
  content: PolicyVerdict,
): PolicyVerdict {
  if (!authorization) return content;
  const priority: Record<PolicyVerdict["decision"], number> = {
    commit: 0,
    review: 1,
    discard: 2,
  };
  const winner = priority[content.decision] > priority[authorization.decision]
    ? content
    : authorization;
  const hits = [...hitList(authorization), ...hitList(content)];
  return {
    decision: winner.decision,
    rule: winner.rule,
    ...(hits.length ? { hits } : {}),
  };
}

/**
 * Runs authorization first, then content policy, and retains the stricter result. Authorization can
 * add review requirements but can never mask a content-based discard.
 */
export function withCapabilityGrantRule(
  store: CapabilityGrantStore,
  contentPolicy: Policy,
): Policy {
  const capabilityRule = createCapabilityGrantRule(store);
  return async (effects, context) => {
    const authorizationVerdict = await capabilityRule(effects, context);
    const contentVerdict = await contentPolicy(effects, context);
    return stricterVerdict(authorizationVerdict, contentVerdict);
  };
}
