#!/usr/bin/env python3
"""
Interval analysis for the per-family miss table published at research/METRICS.md:505-520.

Reads research/corpus/results/results.jsonl directly. Writes nothing. No deps.

Question: the published table ranks families by "over-representation" =
(share of misses)/(share of denominator). Algebraically that equals
(m_i/n_i)/(M/N) = family miss rate / pooled miss rate. So an interval on the
family miss rate maps to an interval on over-representation by dividing by the
pooled rate, and "distinguishable from average" == the interval excludes 1.0x.

Clopper-Pearson (exact, beta quantiles) is the primary interval; Wilson is
printed alongside because that is what research/corpus/REPORT.md publishes.
Fisher's exact test compares each family against the rest of the corpus, with
Holm-Bonferroni across the 14 comparisons.
"""

import json
import math
import os
import sys
from collections import Counter, defaultdict

RESULTS = os.path.join(os.path.dirname(__file__), "..", "corpus", "results", "results.jsonl")


# ---------- regularized incomplete beta, Lentz continued fraction ----------

def _betacf(a, b, x):
    MAXIT, EPS, FPMIN = 300, 3.0e-16, 1.0e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < EPS:
            break
    return h


def betainc(a, b, x):
    """Regularized incomplete beta I_x(a,b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta + b * math.log1p(-x) + a * math.log(x)) * _betacf(b, a, 1.0 - x) / b


def beta_quantile(p, a, b):
    """Inverse of betainc by bisection. Sufficient precision for 4 decimal places."""
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if betainc(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def clopper_pearson(k, n, alpha=0.05):
    """Exact binomial CI. Returns (lo, hi) as proportions."""
    lo = 0.0 if k == 0 else beta_quantile(alpha / 2.0, k, n - k + 1)
    hi = 1.0 if k == n else beta_quantile(1.0 - alpha / 2.0, k + 1, n - k)
    return lo, hi


def wilson(k, n, z=1.959963984540054):
    p = k / n
    d = 1.0 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - h) / d, (c + h) / d


# ---------- Fisher's exact, two-sided, on a 2x2 table ----------

def _lchoose(n, k):
    if k < 0 or k > n:
        return -math.inf
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_exact_two_sided(a, b, c, d):
    """Table [[a,b],[c,d]]: a=family misses, b=family hits, c=other misses, d=other hits."""
    row1, row2 = a + b, c + d
    col1 = a + c
    total = row1 + row2
    lden = _lchoose(total, col1)

    def lp(x):
        return _lchoose(row1, x) + _lchoose(row2, col1 - x) - lden

    obs = lp(a)
    lo = max(0, col1 - row2)
    hi = min(row1, col1)
    tot = 0.0
    for x in range(lo, hi + 1):
        v = lp(x)
        if v <= obs + 1e-9:
            tot += math.exp(v)
    return min(1.0, tot)


def holm(pvals):
    """Holm-Bonferroni adjusted p-values, preserving input order."""
    idx = sorted(range(len(pvals)), key=lambda i: pvals[i])
    m = len(pvals)
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(idx):
        val = (m - rank) * pvals[i]
        running = max(running, val)
        adj[i] = min(1.0, running)
    return adj


# ---------- load ----------

fam_n = Counter()
fam_miss = Counter()
fam_src = defaultdict(Counter)
fam_miss_ids = defaultdict(list)

with open(RESULTS) as fh:
    for line in fh:
        r = json.loads(line)
        if r.get("intent") != "attack" or not r.get("policyDecidable"):
            continue
        f = r["family"]
        fam_n[f] += 1
        fam_src[f][r.get("source", "?")] += 1
        if r.get("miss"):
            fam_miss[f] += 1
            fam_miss_ids[f].append(r["id"])

N = sum(fam_n.values())
M = sum(fam_miss.values())
pooled = M / N

print("=" * 108)
print("PER-FAMILY INTERVALS  (source: research/corpus/results/results.jsonl, recounted, not read from a doc)")
print("=" * 108)
print(f"policy-decidable attacks N = {N}    misses M = {M}    pooled miss rate = {100*pooled:.4f}%")
cp_pool = clopper_pearson(M, N)
w_pool = wilson(M, N)
print(f"pooled Clopper-Pearson 95% = [{100*cp_pool[0]:.2f}%, {100*cp_pool[1]:.2f}%]"
      f"    pooled Wilson 95% = [{100*w_pool[0]:.2f}%, {100*w_pool[1]:.2f}%]")
print()

# ---------- section 1: the n=9 family alone ----------
print("-" * 108)
print("1. resource-and-queue-exhaustion, 1 miss of 9")
print("-" * 108)
k9, n9 = fam_miss["resource-and-queue-exhaustion"], fam_n["resource-and-queue-exhaustion"]
cp = clopper_pearson(k9, n9)
wl = wilson(k9, n9)
print(f"  point miss rate            {100*k9/n9:.2f}%")
print(f"  Clopper-Pearson 95%        [{100*cp[0]:.2f}%, {100*cp[1]:.2f}%]   width {100*(cp[1]-cp[0]):.2f} points")
print(f"  Wilson 95%                 [{100*wl[0]:.2f}%, {100*wl[1]:.2f}%]   width {100*(wl[1]-wl[0]):.2f} points")
print(f"  over-representation point  {(k9/n9)/pooled:.2f}x")
print(f"  over-rep CP 95%            [{cp[0]/pooled:.2f}x, {cp[1]/pooled:.2f}x]")
print(f"  contains pooled {100*pooled:.2f}%?   {'YES' if cp[0] <= pooled <= cp[1] else 'NO'}"
      "   (contains 1.00x over-rep => not distinguishable from average)")
print(f"  0 misses of 9 would give   {(0/n9)/pooled:.2f}x ;  2 of 9 would give {(2/n9)/pooled:.2f}x")
print(f"  the one miss:              {fam_miss_ids['resource-and-queue-exhaustion']}")
print(f"  row provenance:            {dict(fam_src['resource-and-queue-exhaustion'])}")
print()

# ---------- section 2 + 3: every family ----------
print("-" * 108)
print("2/3. Every family. CI is Clopper-Pearson 95% on the family miss rate.")
print("     'over-rep CI' = that CI divided by the pooled rate. Excludes 1.00x => distinguishable.")
print("-" * 108)
rows = sorted(fam_n, key=lambda f: -(fam_miss[f] / fam_n[f]))
pv = []
for f in rows:
    k, n = fam_miss[f], fam_n[f]
    a, b = k, n - k
    c, d = M - k, (N - n) - (M - k)
    pv.append(fisher_exact_two_sided(a, b, c, d))
adj = holm(pv)

hdr = (f"{'family':<32}{'n':>5}{'miss':>6}{'rate%':>8}{'CP 95% on rate':>20}"
       f"{'over-rep':>10}{'over-rep CP 95%':>20}{'Fisher p':>10}{'Holm p':>9}  verdict")
print(hdr)
print("-" * len(hdr))
distinguishable = []
for f, p_raw, p_adj in zip(rows, pv, adj):
    k, n = fam_miss[f], fam_n[f]
    lo, hi = clopper_pearson(k, n)
    orep = (k / n) / pooled
    contains = lo <= pooled <= hi
    if not contains:
        distinguishable.append(f)
    verdict = "overlaps pooled" if contains else ("DISTINGUISHABLE" if p_adj < 0.05 else "excl. pooled, Holm n.s.")
    print(f"{f:<32}{n:>5}{k:>6}{100*k/n:>8.2f}"
          f"{'[' + format(100*lo, '.2f') + ', ' + format(100*hi, '.2f') + ']':>20}"
          f"{orep:>9.2f}x"
          f"{'[' + format(lo/pooled, '.2f') + ', ' + format(hi/pooled, '.2f') + ']':>20}"
          f"{p_raw:>10.4f}{p_adj:>9.4f}  {verdict}")

print()
print(f"families whose CP interval EXCLUDES the pooled rate {100*pooled:.2f}%: "
      f"{len(distinguishable)} of {len(rows)}  -> {distinguishable}")
sig = [f for f, a_ in zip(rows, adj) if a_ < 0.05]
print(f"families significant vs rest-of-corpus, Fisher + Holm, alpha=0.05: {len(sig)} of {len(rows)} -> {sig}")
print()

# ---------- section 4: what a design effect does to n=9 ----------
print("-" * 108)
print("4. Effective n. CLUSTER-INTERVALS.md measures a corpus-level design effect of 10.9x")
print("   on the attack miss rate (14 families as clusters). Within a family the same problem")
print("   recurs one level down: rows are template expansions, not independent trials.")
print("-" * 108)
print(f"{'family':<32}{'n':>5}{'sources':>10}  breakdown")
for f in rows:
    print(f"{f:<32}{fam_n[f]:>5}{len(fam_src[f]):>10}  {dict(fam_src[f])}")
print()
for deff in (2.0, 4.0, 10.9):
    ne = n9 / deff
    ke = k9 / deff
    print(f"  resource-and-queue-exhaustion at design effect {deff:>4}x -> n_eff = {ne:.2f}, k_eff = {ke:.2f}")
print("  A Clopper-Pearson interval needs integer counts, so at n_eff < 9 the interval only widens;")
print("  the [", f"{100*cp[0]:.2f}, {100*cp[1]:.2f}", "] above is the NARROWEST defensible interval for this row.")
print()

# ---------- section 5: the settling number ----------
print("-" * 108)
print("5. Bottom line")
print("-" * 108)
ranked = sorted(fam_n, key=lambda f: -((fam_miss[f] / fam_n[f]) / pooled))
print("  published rank order by over-representation (top 4), with each row's over-rep interval:")
for f in ranked[:4]:
    k, n = fam_miss[f], fam_n[f]
    lo, hi = clopper_pearson(k, n)
    print(f"    {f:<32} {k:>3}/{n:<5} {(k/n)/pooled:>6.2f}x   CI [{lo/pooled:.2f}x, {hi/pooled:.2f}x]")
print()
print("  Do the top-4 intervals separate from each other? Pairwise overlap on the rate CI:")
for i in range(4):
    for j in range(i + 1, 4):
        fi, fj = ranked[i], ranked[j]
        li, hi_ = clopper_pearson(fam_miss[fi], fam_n[fi])
        lj, hj = clopper_pearson(fam_miss[fj], fam_n[fj])
        ov = not (hi_ < lj or hj < li)
        print(f"    {fi:<32} vs {fj:<32} {'OVERLAP' if ov else 'separate'}")
