import { describe, expect, it } from "vitest";
import { asciiPolicySkeleton, UNICODE_SECURITY_VERSION } from "./unicode-security.js";

describe("Unicode security skeleton", () => {
  it("pins the data version used by the comparison", () => {
    expect(UNICODE_SECURITY_VERSION).toBe("17.0.0");
  });

  it("matches the UTS 39 mixed-script examples", () => {
    expect(asciiPolicySkeleton("pаypаl")).toBe(asciiPolicySkeleton("paypal"));
    expect(asciiPolicySkeleton("ѕсоре")).toBe(asciiPolicySkeleton("scope"));
  });

  it("adds compatibility folding for fullwidth protected names", () => {
    expect(asciiPolicySkeleton("ｃｕｓｔｏｍｅｒｓ.ｊｓｏｎｌ"))
      .toBe(asciiPolicySkeleton("customers.jsonl"));
  });

  it("removes Unicode 17 default-ignorable characters", () => {
    const hidden = "cu\u200bst\u2060om\ufeffers";
    expect(asciiPolicySkeleton(hidden)).toBe(asciiPolicySkeleton("customers"));
  });

  it("is idempotent, so repeated policy composition cannot change a result", () => {
    const once = asciiPolicySkeleton("сuѕtоmеrѕ.jsonl");
    expect(asciiPolicySkeleton(once)).toBe(once);
  });
});
