#!/usr/bin/env python3
"""
Is the RANK in research/METRICS.md:505-520 stable, or is it a draw?

The published table orders families by over-representation. Rank is a function of
14 point estimates, four of which sit on denominators under 30. This script asks
directly: if the experiment were rerun, where would resource-and-queue-exhaustion
land?

Two resamplings, both reading research/corpus/results/results.jsonl:
  A. row bootstrap WITHIN each family (the generous assumption: every row an
     independent trial). Family n is held fixed; only which rows are drawn varies.
  B. Bayesian posterior draw per family, Beta(k+0.5, n-k+0.5) Jeffreys, which is
     the same question without the discreteness of a 9-row resample.

Also: the exact deterministic sensitivity, which needs no simulation at all --
what one scenario landing the other way does to each rate.
"""

import json
import math
import os
import random
from collections import Counter

RESULTS = os.path.join(os.path.dirname(__file__), "..", "corpus", "results", "results.jsonl")
SEED = 20260831
BOOTS = 50000

fam_n, fam_miss = Counter(), Counter()
with open(RESULTS) as fh:
    for line in fh:
        r = json.loads(line)
        if r.get("intent") != "attack" or not r.get("policyDecidable"):
            continue
        fam_n[r["family"]] += 1
        if r.get("miss"):
            fam_miss[r["family"]] += 1

fams = sorted(fam_n, key=lambda f: -(fam_miss[f] / fam_n[f]))
N = sum(fam_n.values())
M = sum(fam_miss.values())
TARGET = "resource-and-queue-exhaustion"

print(f"N={N} M={M} pooled={100*M/N:.4f}%   families={len(fams)}   boots={BOOTS} seed={SEED}")
print()

print("-" * 92)
print("Deterministic sensitivity: what ONE scenario landing the other way does to the rate")
print("-" * 92)
print(f"{'family':<32}{'n':>5}{'k':>4}{'rate%':>8}{'k-1 rate%':>11}{'k+1 rate%':>11}{'swing pts':>11}")
for f in fams:
    n, k = fam_n[f], fam_miss[f]
    down = 100 * max(0, k - 1) / n
    up = 100 * (k + 1) / n
    print(f"{f:<32}{n:>5}{k:>4}{100*k/n:>8.2f}{down:>11.2f}{up:>11.2f}{(up - down):>11.2f}")
print()

rng = random.Random(SEED)


def rank_of(rates, target_idx):
    """1-based rank by descending rate; ties share the best rank."""
    r = rates[target_idx]
    return 1 + sum(1 for x in rates if x > r)


def run(sampler, label):
    rank_counts = Counter()
    beats_pooled = 0
    top2 = 0
    ti = fams.index(TARGET)
    for _ in range(BOOTS):
        rates = [sampler(fam_miss[f], fam_n[f]) for f in fams]
        rk = rank_of(rates, ti)
        rank_counts[rk] += 1
        if rk <= 2:
            top2 += 1
        if rates[ti] > M / N:
            beats_pooled += 1
    print("-" * 92)
    print(f"{label}: where does {TARGET} rank?")
    print("-" * 92)
    for rk in sorted(rank_counts):
        pct = 100 * rank_counts[rk] / BOOTS
        bar = "#" * int(pct / 2)
        print(f"  rank {rk:>2}: {pct:>6.2f}%  {bar}")
    print(f"  P(rank == 2, the published rank) = {100*rank_counts[2]/BOOTS:.2f}%")
    print(f"  P(rank <= 2)                     = {100*top2/BOOTS:.2f}%")
    print(f"  P(over-represented at all, rate > pooled) = {100*beats_pooled/BOOTS:.2f}%")
    print()


def boot_sampler(k, n):
    # draw n rows with replacement from a family that is k misses and n-k hits
    p = k / n
    hits = sum(1 for _ in range(n) if rng.random() < p)
    return hits / n


def jeffreys_sampler(k, n):
    return rng.betavariate(k + 0.5, n - k + 0.5)


run(boot_sampler, "A. row bootstrap within family (n fixed, generous: rows treated as independent)")
run(jeffreys_sampler, "B. Jeffreys posterior draw per family")
