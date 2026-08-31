/**
 * A Merkle tree over the journal, hashed the way RFC 9162 (Certificate Transparency 2.0) hashes
 * one, so the proofs this file produces are the shape every transparency-log auditor already knows
 * how to check.
 *
 * Two prefixes carry the whole security argument: a leaf is hashed under 0x00 and an interior node
 * under 0x01. Without the prefixes a leaf whose bytes happen to look like a concatenation of two
 * child hashes could be presented as an interior node, so one tree would have two readings and an
 * "inclusion proof" could be manufactured for a record that was never written. This is the second
 * preimage attack the prefixes exist to kill.
 *
 * Everything here takes and returns leaf HASHES, never raw records, so there is never a question of
 * which side of the hash a caller is on. Use `leafHash()` to cross that line once.
 */
import crypto from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: readonly Buffer[]): Buffer {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}

/** MTH of the empty tree is the hash of the empty string (RFC 9162 section 2.1.1). */
export const EMPTY_ROOT: Buffer = sha256(Buffer.alloc(0));

/** SHA-256(0x00 || entry). The one place raw record bytes become a leaf. */
export function leafHash(entry: string | Buffer): Buffer {
  return sha256(LEAF_PREFIX, typeof entry === "string" ? Buffer.from(entry, "utf8") : entry);
}

/** SHA-256(0x01 || left || right). */
export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

/** the largest power of two strictly smaller than n, for n > 1 */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]) over already-hashed leaves. */
export function merkleRoot(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0]!;
  const k = splitPoint(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/**
 * PATH(m, D[n]): the audit path proving the leaf at `index` is in the tree, smallest first.
 * An auditor holding one record, this path and a signed root never needs the rest of the journal.
 */
export function inclusionProof(leaves: readonly Buffer[], index: number): Buffer[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(`leaf index ${index} is outside a tree of ${leaves.length}`);
  }
  if (leaves.length === 1) return [];
  const k = splitPoint(leaves.length);
  if (index < k) {
    return [...inclusionProof(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))];
  }
  return [...inclusionProof(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))];
}

/**
 * RFC 9162 section 2.1.3.2, verbatim in structure so it can be read against the specification.
 * Rebuilds the root from the leaf and the path; a proof that reconstructs a different root, or that
 * runs out of path before the tree is consumed, fails.
 */
export function verifyInclusion(
  leaf: Buffer,
  index: number,
  treeSize: number,
  proof: readonly Buffer[],
  root: Buffer,
): boolean {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize)) return false;
  if (index < 0 || treeSize <= 0 || index >= treeSize) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

function subProof(leaves: readonly Buffer[], m: number, complete: boolean): Buffer[] {
  if (m === leaves.length) return complete ? [] : [merkleRoot(leaves)];
  const k = splitPoint(leaves.length);
  if (m <= k) {
    return [...subProof(leaves.slice(0, k), m, complete), merkleRoot(leaves.slice(k))];
  }
  return [...subProof(leaves.slice(k), m - k, false), merkleRoot(leaves.slice(0, k))];
}

/**
 * PROOF(m, D[n]): proves the tree of size n extends the tree of size m without rewriting any of the
 * first m records. This is the property that makes an append-only log append-only: a checkpoint an
 * auditor saw last week must still be a prefix of what the journal shows today.
 */
export function consistencyProof(leaves: readonly Buffer[], m: number): Buffer[] {
  if (!Number.isInteger(m) || m <= 0 || m > leaves.length) {
    throw new RangeError(`old tree size ${m} is outside a tree of ${leaves.length}`);
  }
  if (m === leaves.length) return [];
  return subProof(leaves, m, true);
}

/** RFC 9162 section 2.1.4.2, again structured to read against the specification. */
export function verifyConsistency(
  oldRoot: Buffer,
  oldSize: number,
  newRoot: Buffer,
  newSize: number,
  proof: readonly Buffer[],
): boolean {
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize)) return false;
  if (oldSize < 0 || oldSize > newSize) return false;
  if (oldSize === 0) return true;                       // every tree extends the empty tree
  if (oldSize === newSize) return proof.length === 0 && oldRoot.equals(newRoot);

  // when the old size is a power of two its root IS a node of the new tree, and the proof omits it
  const path = (oldSize & (oldSize - 1)) === 0 ? [oldRoot, ...proof] : [...proof];
  if (path.length === 0) return false;

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && fr.equals(oldRoot) && sr.equals(newRoot);
}

/**
 * The same tree, built one leaf at a time in constant amortised work and O(log n) memory.
 *
 * Recomputing MTH from the whole leaf list at every checkpoint costs O(n) each time, which turns
 * boot verification of a long ledger into seconds of hashing for no reason. The tree decomposes
 * into perfect subtrees whose sizes are the binary digits of n, so keeping those peaks and folding
 * them right to left gives exactly the root RFC 9162 defines, at every size, for free.
 */
export class MerkleAccumulator {
  private readonly peaks: Array<{ size: number; hash: Buffer }> = [];
  private count = 0;

  get size(): number {
    return this.count;
  }

  push(leaf: Buffer): void {
    this.peaks.push({ size: 1, hash: leaf });
    this.count += 1;
    for (let i = this.peaks.length - 1; i > 0; i--) {
      const right = this.peaks[i]!;
      const left = this.peaks[i - 1]!;
      if (left.size !== right.size) break;
      this.peaks.splice(i - 1, 2, { size: left.size * 2, hash: nodeHash(left.hash, right.hash) });
    }
  }

  root(): Buffer {
    if (this.peaks.length === 0) return EMPTY_ROOT;
    let root = this.peaks[this.peaks.length - 1]!.hash;
    for (let i = this.peaks.length - 2; i >= 0; i--) root = nodeHash(this.peaks[i]!.hash, root);
    return root;
  }
}
