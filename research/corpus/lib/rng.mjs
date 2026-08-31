// Determinism, so a corpus of thousands of scenarios is a fact rather than a mood.
//
// Every generator draws from one of these and from nothing else: no Math.random, no Date.now, no
// readdir order. Two runs at the same seed produce byte-identical scenario files, which is what
// lets verify-v2.mjs treat the committed corpus as checkable rather than merely plausible.

/** xmur3: string seed to a 32-bit integer, so a generator can be seeded by its own name. */
export function seedFrom(str) {
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  h = Math.imul(h ^ (h >>> 16), 2246822507);
  h = Math.imul(h ^ (h >>> 13), 3266489909);
  return (h ^= h >>> 16) >>> 0;
}

/** mulberry32: 32 bits of state, a full period, and no dependency. */
export function makeRng(seed) {
  let a = typeof seed === "string" ? seedFrom(seed) : seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  next.int = (n) => Math.floor(next() * n);
  next.pick = (arr) => arr[Math.floor(next() * arr.length)];
  next.shuffled = (arr) => {
    const out = arr.slice();
    for (let i = out.length - 1; i > 0; i--) {
      const j = Math.floor(next() * (i + 1));
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  };
  return next;
}

/**
 * The cross product of several parameter lists, walked in a seeded order and cut to `limit`.
 *
 * Enumerating the product and shuffling it, rather than sampling independently, is the difference
 * between "3,000 variants" and "3,000 draws with collisions": every tuple appears at most once and
 * the coverage of each parameter is even by construction.
 */
export function product(lists, rng, limit = Infinity) {
  let tuples = [[]];
  for (const list of lists) {
    const next = [];
    for (const t of tuples) for (const v of list) next.push([...t, v]);
    tuples = next;
  }
  const order = rng.shuffled(tuples);
  return order.slice(0, Math.min(limit, order.length));
}
