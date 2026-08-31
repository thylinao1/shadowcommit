import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import {
  EMPTY_ROOT,
  MerkleAccumulator,
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyConsistency,
  verifyInclusion,
} from "./merkle.js";

const sha = (...parts: Buffer[]) => {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const leaves = (n: number) => Array.from({ length: n }, (_, i) => leafHash(`record-${i}`));

describe("RFC 9162 hashing", () => {
  it("hashes a leaf under 0x00 and a node under 0x01, so a leaf can never be read as a node", () => {
    const d0 = Buffer.from("record-0", "utf8");
    expect(leafHash(d0)).toEqual(sha(Buffer.from([0x00]), d0));
    const l = leafHash("a");
    const r = leafHash("b");
    expect(nodeHash(l, r)).toEqual(sha(Buffer.from([0x01]), l, r));
    // the whole point of the prefixes: the two domains never collide
    expect(leafHash(Buffer.concat([l, r]))).not.toEqual(nodeHash(l, r));
  });

  it("roots the empty tree at the hash of the empty string and a single leaf at itself", () => {
    expect(merkleRoot([])).toEqual(EMPTY_ROOT);
    expect(merkleRoot(leaves(1))).toEqual(leaves(1)[0]);
  });

  it("splits an unbalanced tree at the largest power of two below its size", () => {
    const l = leaves(3);
    // MTH(D[3]) = HASH(0x01 || MTH(D[0:2]) || MTH(D[2:3]))
    const expected = nodeHash(nodeHash(l[0]!, l[1]!), l[2]!);
    expect(merkleRoot(l)).toEqual(expected);
  });
});

describe("inclusion proofs", () => {
  it("proves every record of every tree size from 1 to 33", () => {
    for (let n = 1; n <= 33; n++) {
      const l = leaves(n);
      const root = merkleRoot(l);
      for (let i = 0; i < n; i++) {
        const proof = inclusionProof(l, i);
        expect(verifyInclusion(l[i]!, i, n, proof, root)).toBe(true);
        expect(proof.length).toBeLessThanOrEqual(Math.ceil(Math.log2(n)) + 1);
      }
    }
  });

  it("refuses a proof for a record that is not in the tree", () => {
    const l = leaves(9);
    const root = merkleRoot(l);
    const proof = inclusionProof(l, 4);
    expect(verifyInclusion(leafHash("forged"), 4, 9, proof, root)).toBe(false);
    expect(verifyInclusion(l[4]!, 5, 9, proof, root)).toBe(false);
    expect(verifyInclusion(l[4]!, 4, 9, proof, leafHash("other-root"))).toBe(false);
    expect(verifyInclusion(l[4]!, 9, 9, proof, root)).toBe(false);
  });

  it("refuses a proof whose path was tampered with", () => {
    const l = leaves(12);
    const root = merkleRoot(l);
    const proof = inclusionProof(l, 7);
    const bent = [...proof];
    bent[0] = leafHash("swapped");
    expect(verifyInclusion(l[7]!, 7, 12, bent, root)).toBe(false);
    expect(verifyInclusion(l[7]!, 7, 12, proof.slice(1), root)).toBe(false);
  });
});

describe("consistency proofs", () => {
  it("proves every later tree extends every earlier one up to size 33", () => {
    for (let n = 1; n <= 33; n++) {
      const l = leaves(n);
      const newRoot = merkleRoot(l);
      for (let m = 1; m <= n; m++) {
        const oldRoot = merkleRoot(l.slice(0, m));
        const proof = consistencyProof(l, m);
        expect(verifyConsistency(oldRoot, m, newRoot, n, proof)).toBe(true);
      }
    }
  });

  it("refuses a tree that rewrote a record instead of appending to it", () => {
    const l = leaves(8);
    const oldRoot = merkleRoot(l.slice(0, 5));
    const rewritten = [...l];
    rewritten[2] = leafHash("history-rewritten");
    const proof = consistencyProof(rewritten, 5);
    expect(verifyConsistency(oldRoot, 5, merkleRoot(rewritten), 8, proof)).toBe(false);
  });

  it("refuses a truncated log and a proof for the wrong sizes", () => {
    const l = leaves(10);
    const proof = consistencyProof(l, 6);
    expect(verifyConsistency(merkleRoot(l.slice(0, 6)), 6, merkleRoot(l.slice(0, 9)), 9, proof)).toBe(false);
    expect(verifyConsistency(merkleRoot(l), 10, merkleRoot(l.slice(0, 6)), 6, proof)).toBe(false);
    expect(verifyConsistency(merkleRoot(l.slice(0, 6)), 6, merkleRoot(l), 10, [])).toBe(false);
  });

  it("treats a tree as consistent with itself only under an empty proof", () => {
    const l = leaves(7);
    const root = merkleRoot(l);
    expect(consistencyProof(l, 7)).toEqual([]);
    expect(verifyConsistency(root, 7, root, 7, [])).toBe(true);
    expect(verifyConsistency(root, 7, root, 7, [leafHash("x")])).toBe(false);
  });

  it("rejects an index or size outside the tree instead of guessing", () => {
    const l = leaves(4);
    expect(() => inclusionProof(l, 4)).toThrow(RangeError);
    expect(() => inclusionProof(l, -1)).toThrow(RangeError);
    expect(() => consistencyProof(l, 0)).toThrow(RangeError);
    expect(() => consistencyProof(l, 5)).toThrow(RangeError);
  });
});

describe("the incremental accumulator", () => {
  it("gives the same root as the full computation at every size up to 64", () => {
    const accumulator = new MerkleAccumulator();
    expect(accumulator.root()).toEqual(EMPTY_ROOT);
    const all: Buffer[] = [];
    for (let n = 1; n <= 64; n++) {
      const leaf = leafHash(`record-${n - 1}`);
      all.push(leaf);
      accumulator.push(leaf);
      expect(accumulator.size).toBe(n);
      expect(accumulator.root()).toEqual(merkleRoot(all));
    }
  });

  it("still produces proofs that verify against the accumulated root", () => {
    const accumulator = new MerkleAccumulator();
    const all = leaves(21);
    for (const leaf of all) accumulator.push(leaf);
    const root = accumulator.root();
    for (let i = 0; i < all.length; i++) {
      expect(verifyInclusion(all[i]!, i, all.length, inclusionProof(all, i), root)).toBe(true);
    }
  });
});
