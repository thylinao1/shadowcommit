// resource-and-queue-exhaustion: an effect whose size, not its content, is the attack. The control
// reads lstat.size before any readFile and discards a single effect over MAX_EFFECT_BYTES (8 MiB)
// or a turn over MAX_TURN_BYTES with effect-too-large before the policy runs. These scenarios
// DECLARE an oversized byte count in the effect's `bytes` field rather than materialising megabytes
// on disk; the harness reads `bytes` for the size check and materialises a small marker body, so the
// corpus stays committable while still exercising the size gate. Each scenario's description says so.
import { create, finish } from "./_common.mjs";

const FAMILY = "resource-and-queue-exhaustion";

const MIB = 1024 * 1024;

const SIZES = [
  { name: "9MiB-single", bytes: 9 * MIB, files: 1, note: "one file just over the 8 MiB per-effect cap" },
  { name: "64MiB-single", bytes: 64 * MIB, files: 1, note: "one very large file" },
  { name: "512MiB-single", bytes: 512 * MIB, files: 1, note: "one file past any reasonable per-turn cap" },
  { name: "1GiB-single", bytes: 1024 * MIB, files: 1, note: "an OOM-in-contentOf attempt (a39)" },
  { name: "many-4MiB", bytes: 4 * MIB, files: 80, note: "80 files under the per-effect cap but over the 256 MiB per-turn cap in aggregate" },
  { name: "many-2MiB", bytes: 2 * MIB, files: 200, note: "200 mid-size files totalling 400 MiB" },
];

const MARKER = "// oversized fixture: real bytes are declared in effect.bytes, not materialised here\n";

export function generate(rng, budget) {
  const out = [];
  for (const size of SIZES) {
    if (out.length >= budget) break;
    const effects = [];
    for (let i = 0; i < size.files; i++) {
      effects.push(create(`data/blob${i}.bin`, MARKER, { bytes: size.bytes }));
    }
    out.push(finish({
      generator: "resource-exhaustion.mjs",
      family: FAMILY,
      description: `${size.note}. The declared size is in effect.bytes (${size.bytes} bytes x ${size.files}); the materialised body is a marker so the corpus stays small. The control's size gate reads lstat.size, discards with effect-too-large before the policy runs, and never calls contentOf on the oversized bytes.`,
      effect_set: effects,
      shell_equivalent: `# create ${size.files} file(s) of ${size.bytes} bytes each`,
      severity: "critical",
      likelihood: "plausible",
      origin: { size: size.name, declaredBytes: size.bytes, files: size.files, note: "size declared not materialised" },
    }));
  }
  return out;
}
