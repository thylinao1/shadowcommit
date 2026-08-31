import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  CapabilityGrantStatus,
  parseScopeList,
  scopeText,
  validateGrantForm,
} from "./App";
import type { CapabilityGrant, StoredCapabilityGrant } from "./api";

/** exactly what `GET /api/agents/:id/capability-grant` returns when nobody has issued one */
const DEFAULT_GRANT: CapabilityGrant = {
  agentId: "11111111-1111-4111-8111-111111111111",
  allowedPathGlobs: ["**"],
  allowedDestinations: ["*"],
  budget: Number.MAX_SAFE_INTEGER,
  revision: 0,
  status: "active",
  issuedAt: "default",
  issuedBy: "default",
  revokedAt: null,
  revokedBy: null,
  source: "default",
};

const STORED_GRANT: CapabilityGrant = {
  ...DEFAULT_GRANT,
  allowedPathGlobs: ["src/**"],
  allowedDestinations: ["api.example.test:443"],
  budget: 12,
  revision: 3,
  issuedAt: "2026-08-29T10:00:00.000Z",
  issuedBy: "operator",
  source: "stored",
};

const html = (node: React.ReactElement): string => renderToStaticMarkup(node);

describe("what the panel says about a grant nobody has issued", () => {
  const out = html(<CapabilityGrantStatus state={{ status: "ready", grant: DEFAULT_GRANT }} onRetry={() => {}} />);

  it("says no grant has been issued rather than showing the default as somebody's choice", () => {
    expect(out).toContain("No grant has been issued");
    expect(out).toContain("open default");
    expect(out).toContain("every path");
    expect(out).toContain("every destination");
  });

  it("does not claim the check is off, because it is not", () => {
    // the reviewer's word for this was "inert by default", and it is wrong in a way that matters:
    // the matchers refuse before they compare, so a path leaving the workspace is still held
    expect(out).toContain("does still run");
    expect(out).toContain("leaves the workspace");
    expect(out).not.toContain("no effect");
    expect(out).not.toContain("inert");
  });

  it("does not read as a grant in force", () => {
    expect(out).not.toContain("In force");
    expect(out).not.toContain("Revision 0");
  });

  it("says what pressing Save on the prefilled default would actually do", () => {
    // the form arrives prefilled with **, * and 9007199254740991 and Save is enabled, so one click
    // turns "nobody has issued a grant" into an explicit fully open revision 1 under the operator's
    // name. That is a change of category, and the screen has to say so before it happens.
    expect(out).toContain("saving them unchanged records that open grant as revision 1");
  });
});

describe("what the panel says about a grant an operator issued", () => {
  it("names the revision, who issued it, and that the policy reads it live", () => {
    const out = html(<CapabilityGrantStatus state={{ status: "ready", grant: STORED_GRANT }} onRetry={() => {}} />);
    expect(out).toContain("Revision 3");
    expect(out).toContain("operator");
    expect(out).toContain("In force");
    expect(out).not.toContain("No grant has been issued");
  });

  it("says what a revoked grant does to the next turn, and what it does not do to a held one", () => {
    const revoked: CapabilityGrant = {
      ...STORED_GRANT,
      status: "revoked",
      revision: 4,
      revokedBy: "operator",
      revokedAt: "2026-08-29T11:00:00.000Z",
    };
    const out = html(<CapabilityGrantStatus state={{ status: "ready", grant: revoked }} onRetry={() => {}} />);
    expect(out).toContain("Revoked by operator");
    expect(out).toContain("held for a person from the next judgement on");
    expect(out).toContain("including one running right now");
    // the boundary the approve path really has: a revoked grant does not settle a held turn
    expect(out).toContain("still yours to approve or reject");
    expect(out).not.toContain("In force");
  });

  it("does not say a revoked grant holds every turn, because a turn with no effects commits", () => {
    // capability-grant-rule.ts returns null on an empty effect list before it reaches the
    // revocation check, so the unqualified sentence was false for that turn
    const revoked: CapabilityGrant = { ...STORED_GRANT, status: "revoked", revision: 4, revokedBy: "operator" };
    const out = html(<CapabilityGrantStatus state={{ status: "ready", grant: revoked }} onRetry={() => {}} />);
    expect(out).toContain("carries an effect at all is held");
    expect(out).toContain("proposes nothing is not authorized and not held");
  });

  it("does not attribute a grant nobody issued to an actor named default", () => {
    // revoke on an Agent that never had a grant synthesises one, stamps issuedBy "default" and a
    // real timestamp on it, and bumps past revision 1. "Revision 2, issued by default at 10:04"
    // names an issuer who does not exist.
    const synthesized: CapabilityGrant = {
      ...DEFAULT_GRANT,
      status: "revoked",
      revision: 2,
      issuedAt: "2026-08-29T11:00:00.000Z",
      issuedBy: "default",
      revokedBy: "operator",
      revokedAt: "2026-08-29T11:00:00.000Z",
      source: "stored",
    };
    const out = html(<CapabilityGrantStatus state={{ status: "ready", grant: synthesized }} onRetry={() => {}} />);
    expect(out).toContain("Revision 2");
    expect(out).toContain("carried forward from the server");
    expect(out).not.toContain("issued by default");
    expect(out).toContain("Revoked by operator");
  });

  it("reads a PUT response, which carries no source at all, as a grant in force", () => {
    // The server sends `source` only on the GET path: PUT returns store.issue(...) and DELETE
    // returns store.revoke(...), neither of which sets it. The panel was right by accident, because
    // `undefined === "default"` is false. Written the other way round it would have told an
    // operator "No grant has been issued" one line after they issued one.
    const put: StoredCapabilityGrant = {
      agentId: STORED_GRANT.agentId,
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["api.example.test:443"],
      budget: 12,
      revision: 4,
      status: "active",
      issuedAt: "2026-08-29T12:00:00.000Z",
      issuedBy: "operator",
      revokedAt: null,
      revokedBy: null,
    };
    const out = html(
      <CapabilityGrantStatus state={{ status: "ready", grant: { ...put, source: "stored" } }} onRetry={() => {}} />,
    );
    expect(out).toContain("Revision 4");
    expect(out).toContain("In force");
    expect(out).not.toContain("No grant has been issued");
    expect(out).not.toContain("open default");
  });
});

describe("a grant the panel could not read", () => {
  const out = html(
    <CapabilityGrantStatus state={{ status: "error", message: "Authentication required" }} onRetry={() => {}} />,
  );

  it("says it could not be read and carries the reason", () => {
    expect(out).toContain("could not be read");
    expect(out).toContain("Authentication required");
    expect(out).toContain('role="alert"');
    expect(out).toContain("Try reading the grant again");
  });

  it("does not fall back to the open default, which would be the reassuring lie", () => {
    expect(out).not.toContain("No grant has been issued");
    expect(out).not.toContain("open default");
    expect(out).not.toContain("In force");
  });
});

describe("a grant the panel has not read yet", () => {
  it("says it is reading rather than describing a grant", () => {
    const out = html(<CapabilityGrantStatus state={{ status: "loading" }} onRetry={() => {}} />);
    expect(out).toContain("Reading the grant");
    expect(out).not.toContain("open default");
    expect(out).not.toContain("In force");
    expect(out).not.toContain("could not be read");
  });
});

describe("reading the scope fields an operator typed", () => {
  it("takes one entry per line, one per comma, and both at once", () => {
    expect(parseScopeList("src/**")).toEqual(["src/**"]);
    expect(parseScopeList("src/**\ndocs/**")).toEqual(["src/**", "docs/**"]);
    expect(parseScopeList("src/**, docs/**")).toEqual(["src/**", "docs/**"]);
    expect(parseScopeList("src/**,\n  docs/** \n")).toEqual(["src/**", "docs/**"]);
  });

  it("drops blank lines and trailing whitespace instead of sending empty entries", () => {
    expect(parseScopeList("\n\n")).toEqual([]);
    expect(parseScopeList("  ")).toEqual([]);
    expect(parseScopeList("src/**\n\n\ndocs/**\n")).toEqual(["src/**", "docs/**"]);
  });

  it("round-trips what the server sent back into the box it came from", () => {
    expect(parseScopeList(scopeText(["src/**", "test/**"]))).toEqual(["src/**", "test/**"]);
    expect(scopeText(["**"])).toBe("**");
  });

  it("keeps a brace glob whole instead of cutting it in half at its own comma", () => {
    // `src/{a,b}/**` became `src/{a` and `b}/**`. Both halves passed validation and were stored as
    // the operator's authorization scope, and neither can ever match anything, because
    // globExpression escapes braces. The operator narrowed the grant and every turn after it was
    // held under capability-path-out-of-scope with nothing saying why.
    expect(parseScopeList("src/{a,b}/**")).toEqual(["src/{a,b}/**"]);
    expect(parseScopeList("src/{a,b,c}/**\ndocs/**")).toEqual(["src/{a,b,c}/**", "docs/**"]);
    // a line with no brace still splits on commas, which is the shorthand this box was built for
    expect(parseScopeList("src/**, docs/**\napps/{web,server}/**")).toEqual([
      "src/**",
      "docs/**",
      "apps/{web,server}/**",
    ]);
  });
});

describe("refusing a grant form that would mean something nobody typed", () => {
  const valid = { pathGlobs: "src/**", destinations: "*", budget: "8" };

  it("accepts a filled form and sends the parsed lists", () => {
    const checked = validateGrantForm(valid);
    expect(checked.ok).toBe(true);
    expect(checked.ok && checked.body).toEqual({
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["*"],
      budget: 8,
    });
  });

  it("refuses an empty path list, an empty destination list, and every non-budget", () => {
    // the axis, not the one value: each of these reached the server as a 400 or as NaN before
    const refusals = [
      { ...valid, pathGlobs: "" },
      { ...valid, pathGlobs: "  \n " },
      { ...valid, destinations: "" },
      { ...valid, destinations: ",\n," },
      { ...valid, budget: "" },
      { ...valid, budget: "   " },
      { ...valid, budget: "eight" },
      { ...valid, budget: "-1" },
      { ...valid, budget: "1.5" },
      { ...valid, budget: "1e400" },
      { ...valid, budget: "9007199254740993" },
    ];
    for (const form of refusals) {
      const checked = validateGrantForm(form);
      expect([JSON.stringify(form), checked.ok]).toEqual([JSON.stringify(form), false]);
      expect(!checked.ok && checked.message.length > 0).toBe(true);
    }
  });

  it("names the field that is wrong rather than giving one message for everything", () => {
    const globs = validateGrantForm({ ...valid, pathGlobs: "" });
    const destinations = validateGrantForm({ ...valid, destinations: "" });
    const budget = validateGrantForm({ ...valid, budget: "eight" });
    expect(!globs.ok && globs.message).toContain("path glob");
    expect(!destinations.ok && destinations.message).toContain("destination");
    expect(!budget.ok && budget.message).toContain("Budget");
  });

  it("accepts zero as a budget, which is a real setting and not an empty field", () => {
    const checked = validateGrantForm({ ...valid, budget: "0" });
    expect(checked.ok && checked.body.budget).toBe(0);
  });

  it("refuses every glob and destination the server answers with a 500, and says which one", () => {
    // Measured against the real route: normalizeCapabilityGrantInput throws a plain TypeError and
    // app.ts maps only ZodError and HttpError to a 4xx, so each of these came back as HTTP 500 with
    // the TypeError text as the body. The axis, not the one value a screenshot showed.
    const globs = ["/etc/**", "../**", "./src/**", "src/../../etc/**", "C:/windows/**", "..\\etc\\**"];
    for (const glob of globs) {
      const checked = validateGrantForm({ ...valid, pathGlobs: glob });
      expect([glob, checked.ok]).toEqual([glob, false]);
      expect([glob, !checked.ok && checked.message.includes(glob)]).toEqual([glob, true]);
      expect([glob, !checked.ok && checked.message.includes("Path globs")]).toEqual([glob, true]);
    }

    const destinations = [
      "https://api.example.com",
      "https://api.example.com/v1",
      "user@example.com",
      "a b.com",
      "example.com/?x=1",
      "example.com/#top",
      "/only-a-path",
    ];
    for (const destination of destinations) {
      const checked = validateGrantForm({ ...valid, destinations: destination });
      expect([destination, checked.ok]).toEqual([destination, false]);
      expect([destination, !checked.ok && checked.message.includes(destination)]).toEqual([destination, true]);
      expect([destination, !checked.ok && checked.message.includes("Destinations")]).toEqual([destination, true]);
    }
  });

  it("still accepts the shapes the server does, so the client check is not stricter than it", () => {
    const accepted: Array<[string, string]> = [
      ["src/**", "*"],
      ["src/{a,b}/**", "api.example.test"],
      ["apps/web/src/*.ts", "api.example.test:443"],
      ["**", "registry.example.test/npm/**"],
      ["a/b/c.txt", "[::1]:8080"],
    ];
    for (const [pathGlobs, destinations] of accepted) {
      const checked = validateGrantForm({ pathGlobs, destinations, budget: "4" });
      expect([pathGlobs, destinations, checked.ok]).toEqual([pathGlobs, destinations, true]);
    }
  });

  it("reads a budget as digits, because Number accepted things the message does not promise", () => {
    // the field is labelled "the most effects one turn may propose" and the refusal says a whole
    // number; bare Number() took 0x10 as 16, 1e3 as 1000, +3 as 3, 5.0 as 5 and -0 as 0
    for (const budget of ["0x10", "1e3", "+3", "5.0", "-0", " 12 ", "١٢", "1_000", "Infinity"]) {
      const checked = validateGrantForm({ ...valid, budget });
      expect([budget, checked.ok]).toEqual([budget, budget === " 12 "]);
    }
    expect(validateGrantForm({ ...valid, budget: " 12 " })).toEqual({
      ok: true,
      body: { allowedPathGlobs: ["src/**"], allowedDestinations: ["*"], budget: 12 },
    });
  });
});
