import {
  asciiConfusablePrototype,
  isDefaultIgnorableCodePoint,
  UNICODE_SECURITY_VERSION,
} from "./unicode-confusables.generated.js";

export { UNICODE_SECURITY_VERSION };

/**
 * A comparison-only Unicode skeleton for ASCII security policy names.
 *
 * Unicode UTS #39 says a skeleton is an internal comparison form, not a normalized identifier.
 * That distinction is load-bearing here: this value may decide whether a path is protected, but it
 * must never become the path's identity key. The latter would merge legitimate names from different
 * languages in grants, touch accounting and file identity.
 *
 * UTS #39's internal skeleton begins with NFD. Protected policy names are ASCII, so this profile
 * begins with NFKD as a deliberate compatibility extension: fullwidth and presentation forms must
 * compare with the ASCII name they display as. Default-ignorable ranges and confusable prototypes
 * are pinned to Unicode 17.0.0 in the generated module.
 */
export function asciiPolicySkeleton(input: string): string {
  let skeleton = "";
  for (const character of input.normalize("NFKD")) {
    const codePoint = character.codePointAt(0)!;
    if (isDefaultIgnorableCodePoint(codePoint)) continue;
    skeleton += asciiConfusablePrototype(codePoint) ?? character;
  }
  return skeleton.normalize("NFD").toLowerCase().normalize("NFD");
}

