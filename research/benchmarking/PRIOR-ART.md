# Prior art: what the field actually publishes, and what it measures it on

This is a survey built to answer one question. Shadow Commit holds 17.26% of benign turns for a
person, destroys 1.26% outright, and misses 3.64% of attacks on the corpus it was tuned against
against 35.3% on a blind set. Are those numbers good or bad relative to published work?

Nobody had checked. This file is the check. `POSITIONING.md` is the answer.

## The rule this file follows

Every number below carries the source it came from and a note on whether it was measured on data the
system was built against. Where a number could not be verified it says so rather than appearing
clean. Where the field publishes nothing, the absence is recorded as a finding, because for the
question being asked an absence is often the answer.

## How much of this is verified, stated honestly

Three levels, and the table entries say which applies.

| Level | What was done | Coverage |
|---|---|---|
| Source resolves | The arXiv ID or URL was fetched and returns the document it claims | 80 of 80 sources. 59 arXiv IDs all resolve, 21 non-arXiv URLs all return HTTP 200 |
| Title matches | The claimed title matches the real title at that identifier | 62 of 63 arXiv-backed claims. The one exception is cosmetic, a section reference in the title field pointing at the right paper |
| Number verified | The document was reopened and the number quoted from it | Partial, and each row says. The anchors were verified by hand |

Number-level verification ran in two passes. A first adversarial pass covered 17 claims before the
session hit a rate limit that killed 87 agents mid-run. A second pass reopened all 43 source
documents behind the load-bearing claims and completed 43 of 43 with zero errors. Final tally across
105 citations:

| Status | Count |
|---|---|
| Hand verified by the main session, source read directly | 8 |
| CONFIRMED by an independent verifier that reopened the source | 42 |
| CORRECTED by that verifier, and every correction applied to this document | 6 |
| Source resolves and title matches, but the figure was not independently requoted | 49 |
| REFUTED | 0 |
| UNVERIFIABLE | 0 |

**No fabricated or misattributed source was found anywhere in the load-bearing set.** Everything used
in `POSITIONING.md` is either hand verified or carries a verdict. The 49 rows marked source only are
leads, not citations, and should not be quoted without reopening them.

The six corrections are worth naming, because they are the kind of error this process exists to
catch. Two were per-defence figures read off a bar chart rather than stated in prose. One attached a
number from a different experiment to the wrong comparison sequence. One took a single model's column
as an average across five models. One mislabelled a within-benchmark decomposition as a
tuned-versus-blind split. One attributed a figure to the wrong Anthropic document.

The anchors below were opened, downloaded and read directly rather than taken from an agent: CaMeL,
Cordon, AgentDyn, AgentDojo, Cautious Bench, Oversight Has a Capacity, and the Alahmadi SOC study.

---

## 1. Agent action-gating and policy systems

The closest family to Shadow Commit: systems that sit between an agent and its effects and decide
whether an action proceeds. The question that matters here is not how many attacks they stop. It is
what they cost on benign work, because that is the axis 17.26% lives on.

### The headline finding of this family

Of roughly sixteen systems surveyed, **four publish anything at all about the benign-side cost of
their gate, and only one of those four measures it on a benchmark the authors did not build.**

| System | Venue | Benign-side number published | Measured on |
|---|---|---|---|
| RTBAS | arXiv [2502.08966](https://arxiv.org/abs/2502.08966), CMU, 2025 | False positive rate 8.1% (LM judge) and 16.2% (attention), against 29% for confirm-every-time | 37 test cases the authors wrote themselves. Tuned |
| AgentArmor | arXiv [2508.01249](https://arxiv.org/abs/2508.01249), ByteDance, 2025 | False positive rate averaging 2.6%, never above 4%. Verified caveat: that is GPT-4o's per-attack-type column in Table 2, not an average across the five evaluated models; GPT-4o-mini reaches 19% in the same table | AgentDojo and ASB, third party. The only held-out FALSE POSITIVE RATE in the family, and on that metric it is better than anything we publish |
| Progent | arXiv [2504.11703](https://arxiv.org/abs/2504.11703), 2025 | 6% of policy updates require human approval | AgentDojo, but see the denominator problem below |
| CaMeL | arXiv [2503.18813](https://arxiv.org/abs/2503.18813), Google DeepMind, 2025 | Measures the right quantity and publishes no number for it. Figure 10 only | AgentDojo. Tuned |

Everyone else publishes nothing on the benign side. ACE (NDSS 2026, arXiv
[2504.20984](https://arxiv.org/abs/2504.20984)) reports a 100% security score on 1,054 InjecAgent
cases with no undefended utility baseline, no plan-rejection rate and no false positives. Task Shield
(ACL 2025) reports no FPR and no human-hold rate. FIDES (Microsoft, arXiv
[2505.23643](https://arxiv.org/abs/2505.23643)) contains zero occurrences of "approval" or "user
confirm" in its full text; its human-in-the-loop option exists only in the shipped product
documentation, not in the paper.

### RTBAS is the closest published comparison to 17.26% that exists

Its false positive rate is defined as tool calls flagged for user confirmation that did not in fact
involve propagation of private data, which is the same shape as a benign turn held for a person.

> "the LM-Judge approach and the attention-based approach achieve an FPR of 8.1% and 16.2% across all
> test suites, respectively, whereas GPTs exhibit FPRs of 29%."

Source: <https://arxiv.org/pdf/2502.08966>. Verified: source resolves, title matches, number quoted
by a verifier that reopened the PDF.

Two things about it. The 16.2% figure sits almost exactly on our 17.26%. And the denominator is 37
test cases the RTBAS authors wrote themselves, which by this repository's own standard is a tuned
number, so it should be set against our tuned 17.26% rather than against a blind figure of ours.
Set against our 23.88% hold rate over 19,102 real commits, RTBAS is the better number.

RTBAS also publishes a benign utility degradation with no attack present, 10% for the LM judge
screener and 7.4% for the attention screener on AgentDojo, and notes the Slack suite falls to 22%
and 33%. That is the only held-out benign UTILITY DEGRADATION in this family, as distinct from
AgentArmor's held-out false positive rate. Those are two different metrics and each has exactly one
held-out instance.

### The Progent denominator problem, which matters

Progent's 6% reads like a human-ask rate and is not one.

> "We also observe that, after the SMT-based expansion check, only 6% of policy updates are
> expansions that require approval; the rest are narrowings handled automatically."

The denominator is **policy updates**, not tasks and not actions. A run with one policy update and a
hundred tool calls contributes one to that denominator. Worse for read-across: the headline ASR of
1.0% was measured in Auto-Approve mode, with a simulated user who approves every expansion, so the
6% is never exercised in the result the paper leads with. Quoting 6% beside our 17.26% would be a
category error and this document does not do it.

### CaMeL measures our exact metric and publishes no number

This is the single most useful fact in the family, and it was verified by reading the PDF directly.

CaMeL's deployment mode is a human hold, not a block:

> "If a policy violation is detected (e.g., private data passed to a tool with side effects), the
> tool's execution is blocked. In a real-world application, executions that violate security policies
> will not be blocked, but they will require user confirmation." (page 10)

It measures how often that fires:

> "We show in Figure 10 for how many tasks security policies deny tool execution, i.e., how often
> users are asked for explicit consent before executing a given tool."

And it publishes that only as a per-model, per-suite bar chart. No aggregate in the text, no table,
proportions computed only over successfully-solved tasks. There is no CaMeL benign human-hold
percentage a person can cite.

The paper then names the resulting problem in a section heading, "9.2 De-classification and user
fatigue":

> "While CaMeL can prevent many prompt injection attacks, it may also require user intervention in
> situations where the security policy is too restrictive or ambiguous. [...] This can lead to user
> fatigue, where users become desensitized to security prompts and may inadvertently approve
> malicious actions"

and again in 9.3: "CaMeL also comes with a user burden."

A full-text search of the PDF returns zero hits for "false positive", "over-block" and "spurious",
and one hit for "too restrictive", in prose, with no number attached.

### Other systems in the family, for completeness

| System | Attack-side result | Benign-side | Source |
|---|---|---|---|
| Conseca (Google Research, HotOS 25) | no ASR published | 12.0/20 tasks against 14.0/20 with no policy, a 10 point absolute utility loss | [2501.17070](https://arxiv.org/abs/2501.17070) |
| IsolateGPT / SecGPT (NDSS 2025) | 20.2% of attacks succeed undefended | 7.6% permission-dialog rate on ATTACK traffic; benign dialog rate not measured | [2403.04960](https://arxiv.org/abs/2403.04960) |
| AgentSandbox | see source | benign utility 82.00% against 83.81% undefended, a 1.81 point cost | source only |
| Task Shield | ASR 2.07% from 47.69% | none published, single trial per task | ACL 2025 |
| f-secure | 0% ASR on InjecAgent, four models | see source | source only |
| ACE | 100% security on 1,054 InjecAgent cases | none published | [2504.20984](https://arxiv.org/abs/2504.20984) |

Note the pattern in the attack column: 100%, 0% ASR, 2.07%. These are the numbers a system reports
about data its authors chose. Section 5 is about what happens to numbers like these on data the
authors did not choose.

---

## 2. Agent safety and guardrail benchmarks

The benchmarks the family above is scored on. What matters here is which of them measure a benign
cost at all, because a benchmark that only scores the attack side cannot penalise a defence that
works by refusing everything.

| Benchmark | Venue | Attack-side headline | Benign side measured? |
|---|---|---|---|
| AgentDojo | arXiv [2406.13352](https://arxiv.org/abs/2406.13352), NeurIPS 2024 D&B | GPT-4o undefended: targeted ASR 47.69%, benign utility 69.00% (Table 3). The defence table's no-defence row reads 57.69% under a different attack configuration; both are in the paper and they are not a contradiction | Yes, benign utility is a headline column with 95% intervals |
| InjecAgent | arXiv [2403.02691](https://arxiv.org/abs/2403.02691), ACL Findings 2024 | ReAct GPT-4 ASR-valid 23.6%, 47.0% with a hacking prompt | No. Every one of the 1,054 cases contains an injection. No benign control set exists |
| R-Judge | arXiv [2401.10019](https://arxiv.org/abs/2401.10019), EMNLP Findings 2024 | GPT-4o F1 74.45, recall 85.00 | Yes. Specificity on safe cases is 1 minus the false positive rate |
| ToolEmu | see source | GPT-4 failure incidence 39.4% | Partial |
| AgentHarm | see source | GPT-4o harm score 48.4% | Partial, via a refusal score |
| Agent Security Bench | see source | highest average ASR 84.30% | Yes, Table 19 reports no-attack performance under each defence |
| Agent-SafetyBench | see source | no agent exceeds 60% total safety | Partial |
| ST-WebAgentBench | see source | raw completion 24.3% average, falls under policy | Yes, completion-under-policy is the metric |

AgentDojo is the reference point the rest of the field compares against, and it is better than its
reputation on this axis. It reports benign utility as a mandatory column, so a defence that buys
security by refusing work is visibly penalised, and it reports 95% confidence intervals in Table 5.
Its own defence table, GPT-4o:

| Defence | Benign utility | Utility under attack | Targeted ASR |
|---|---|---|---|
| None | 69.0% | 50.01% | 57.69% |
| Delimiting | 72.66% | 55.64% | 41.65% |
| Prompt injection detector | 41.49% | 21.14% | 7.95% |
| Repeat prompt | 85.53% | 67.25% | 27.82% |
| Tool filter | 73.13% | 56.28% | 6.84% |

The prompt injection detector buys an ASR drop from 57.69% to 7.95% by giving up 27.51 points of
benign utility, a 40% relative loss. The paper names the cause in plain words:

> "The prompt injection detector has too many false positives, however, and significantly degrades
> utility."

It names the false positives and never quantifies them as a rate. The cost is visible only through
its effect on task success. That is the pattern across this whole family.

One more AgentDojo result matters for the blind-set question. The same agent goes from 3.66% to
57.7% targeted ASR purely by swapping the injection template, roughly a sixteenfold swing from
attack phrasing alone. Attack-side numbers in this field are extremely sensitive to who wrote the
attacks.

---

## 3. Over-safety: the 2026 wave that measures what we measure

Going into this survey the working assumption was that nobody publishes a benign-side refusal rate.
That was correct for the classics and wrong for 2026. Two papers published this year measure
precisely the quantity 17.26% describes, and both were verified by reading the PDF.

### Cautious Bench, "The Guard That Cried Wolf"

arXiv [2608.27009](https://arxiv.org/abs/2608.27009), Zhang, Xie and Chen, August 2026. It describes
itself as "to our knowledge the first benchmark to make over-safety the construct for agent
guardrails". 756 decidable benign and twin pairs rendered under three object-name grades, 2,268
measured pairs, plus 40 undecidable pairs reported separately.

> "All six non-floor guardrails over-refuse authorized Decidable actions, with as-authored FP from
> 35 to 89% across the non-floor guards"

False positive rate at the as-authored surface, over 756 benign cells:

| Guardrail | FP % |
|---|---|
| PIGuard | 89 |
| AgentDoG-Qwen | 70 |
| R-Judge | 58 |
| AgentDoG-Llama | 49 |
| ToolEmu | 36 |
| TS-Guard | 35 |
| LlamaGuard | 1 |

LlamaGuard's 1% is not a good score. The paper calls it "a content-safety floor" and "a 1% floor;
detection co-moves with FP", with undecidable detection of 2. It earns a low false positive rate by
not engaging with execution safety at all.

The paper also finds guardrails read the label rather than the policy. Under innocent, as-authored
and scary object names: AgentDoG-Qwen 63 to 70 to 82, TS-Guard 34 to 35 to 66, ToolEmu 32 to 36 to
45. "Since only the object name varies [...] the deviation is the name's doing: the guardrails read
the surface label, not the authorization context."

**The caveat that must travel with this number.** Its 756 benign cells are deliberately boundary
cases, built as twins of unauthorized actions, "at the boundary an authorized action resembles an
unauthorized one". That is an adversarially hard benign set, not ordinary work. And its FP is a hard
refusal, where our 17.26% is a hold a person can approve. The paper disclaims deployment read-across
itself: "We build a benchmark and a validity argument for its labels, not a guardrail, and claim
nothing about deployed refusal rates." So this establishes that over-refusal at scale is normal in
this field. It does not license a claim that we are two to five times better.

### "Oversight Has a Capacity"

arXiv [2606.08919](https://arxiv.org/abs/2606.08919), Emre Turan, June 2026. The only source found
that treats the human-ask rate as a resource-allocation problem with an interior optimum.

Its model, verbatim: a threshold theta with auto-allow iff score < theta else escalate; an asymmetric
cost where "auto-allowing a dangerous action (a miss) is catastrophic; escalating a safe one (a false
alarm) is annoyance"; and "a reviewer model h(a, l) with reliability r(l) that decreases in
cumulative escalation load l. This is the endogenous element: l is driven by the guard's own
escalation rate."

The reliability function, which is the calibratable part:

```
r(l) = max( r_min , 1 - slope * max(0, l - C) )       slope = 0.02, r_min = 0.2
```

"the reviewer is reliable up to C reviews, then degrades."

Table 2, the optimum and how it moves:

| reviewer capacity C | optimal escalation rate | danger through at optimum | danger through at full escalation |
|---|---|---|---|
| 10 | 64% | 56% | 69% |
| 25 | 64% | 42% | 57% |
| 50 | 72% | 22% | 39% |

> "Escalating everything is strictly worse than the optimum, and the optimum shifts with capacity."

It also measures the label noise floor: three persona reviewers on the same 125 actions reach
Fleiss' kappa 0.52, with the pragmatic reviewer calling 87 actions safe against the cautious
reviewer's 45, and the persona majority matching the gold label 74% of the time. "A guard cannot be
scored against one objective truth; the agreement ceiling is the honest yardstick."

**The limit, in the authors' own words, and it is severe.** "We state this up front: the inverted-U
below is a direct consequence of the assumed monotonically-fatiguing reviewer [...] a modeling result
about a plausible model, not an empirical finding about real people." The 125-action set is
"deliberately weighted to hard cases". So 64% and 72% are outputs of a simulation on a hard set and
are **not** a target to calibrate a real hold rate against. What transfers is the shape and the
method, not the level.

---

## 4. What happens to these defences on data they did not see

This is the section that decides whether a 3.64% to 35.3% gap is a scandal or a Tuesday.

### The single strongest result: nine defences at once, on a benchmark built after them

AgentDyn, arXiv [2602.03117](https://arxiv.org/abs/2602.03117), Li, Wen, Shi, Zhang, Vorobeychik and
Xiao. 60 open-ended tasks, 560 injection cases. Every defence it scores predates it, so it is
genuinely held out for all of them. Verified by reading the PDF.

> "These defenses achieve strong performance on existing agent security benchmarks. Some even
> maintain near-zero ASR on the most advanced AgentDojo benchmark, with almost no utility drop
> compared to having no defense. However, none of them attain acceptable performance for real-world
> deployment on AgentDyn."

Table 3, utility with no attack, GPT-4o unless noted, against the 53.33% undefended agent:

| Defence | Utility, no attack | Utility retained | ASR |
|---|---|---|---|
| None (vanilla) | 53.33% | baseline | 37.80% |
| ProtectAI | 0.00% | 0.0% | 0.85% |
| CaMeL | 0.00% | 0.0% | 0.00% |
| Progent | 6.67% | 12.5% | 1.69% |
| Tool Filter | 8.33% | 15.6% | 4.22% |
| PIGuard | 10.00% | 18.8% | 1.67% |
| DRIFT | 30.00% | 56.3% | 0.83% |
| Meta SecAlign (70B) | 55.00% | 103% | 8.98% |

CaMeL scores 0.00% utility, 0.00% ASR on all four base models. The paper explains why: "This static
strategy is difficult to handle the open-ended tasks, resulting in zero utility and zero ASR across
all agents on our fully open-ended benchmarks." A perfect security score bought by completing no
work at all. This is the flagship security-by-design system, and its own paper reports 77% of tasks
solved with provable security.

The field's verdict on itself, same paper: "after surveying recent papers from top-tier AI and
security venues, we found that the majority of community effort (79%) focuses on defenses, yet
almost none of them are readily deployable in practice."

### Adaptive attacks: near-zero becomes near-total

| Study | Result | Source |
|---|---|---|
| 12 published defences bypassed | above 90% adaptive ASR "for most", where "the majority of defenses originally reported near-zero". Confirmed per-defence from prose: Meta-SecAlign 2% to 96%, Circuit Breakers to 100%, Spotlighting and Prompt Sandwiching jointly "as low as 1%" to "above 95% for both". PIGuard is the stated outlier at 71%. Per-defence figures beyond these come from reading Figure 1's bars and are not independently assignable | [2510.09023](https://arxiv.org/abs/2510.09023) |
| DataSentinel (IEEE S&P 2025) under DataFlip | false negative rate 0.0% on the attack it was tuned against, 76.0% to 100.0% under DataFlip. Detection 0% on 4 of 7 tasks; the best, 24.0%, is on the task used to train it | [2507.05630](https://arxiv.org/abs/2507.05630) |
| Eight IPI defences on InjecAgent | LLM detector detection 72% to 0%; total ASR 0.02 to 0.57 on Llama3-8B, roughly 28x. All eight exceed 50% adaptive ASR | [2503.00061](https://arxiv.org/abs/2503.00061) |
| Meta-SecAlign-8B under PISmith | avg ASR@1 0.04 static to 0.87, roughly 22x. Trained on 100 samples, generalised to all 12 unseen benchmarks | [2603.13026](https://arxiv.org/abs/2603.13026) |
| Ten production guardrails, public against private prompts | Qwen3Guard-8B 91.0% to 33.8%, a 57.2 point drop. WildGuard-7B 87.1 to 41.5. Best generaliser Granite-Guardian-3.2-5B 56.2 to 49.7 | [2511.22047](https://arxiv.org/abs/2511.22047) |
| MetaSecAlign-8B, SecInfer, PromptLocate on a new corpus | under the same Combined attack, MetaSecAlign-8B 0.00 / 0.01 / 0.00 on OPI, InjecAgent and AgentDojo becomes 0.78 on LongPIBench; SecInfer 0.91. Caveat: LongPIBench comes from the same lab as several defences it tests, so it is not fully independent | [2608.28411](https://arxiv.org/abs/2608.28411) |

The quote that sums the family up, from the twelve-defence study:

> "we bypass 12 recent defenses (based on a diverse set of techniques) with attack success rate above
> 90% for most; importantly, the majority of defenses originally reported near-zero attack success
> rates."

---

## 5. The tuned-to-blind ratio table

This is the section that answers the question directly. Every row is the same detector scored twice,
once on the data it was developed against and once on data it was not, with the ratio between them.
Ratios are given in **error terms** (miss rate, false negative rate, or 1 minus F1) because that is
the quantity Shadow Commit's 3.64% and 35.3% are measured in. A ratio computed on F1 or accuracy
looks far smaller for the same underlying collapse, and mixing the two is the easiest way to
mislead with this table.

| Detector | Tuned | Blind | Error ratio | What made it blind | Source |
|---|---|---|---|---|---|
| Transcend, DREBIN on Marvin | miss 8% | miss 64.2% | **8.0x** | Different dataset, later period, other authors | [USENIX Sec 17](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-jordaney.pdf) |
| TESSERACT, DREBIN | F1 0.91 | F1 0.58 | **4.7x** | Time split only, malware ratio held at 10% | [USENIX Sec 19](https://www.usenix.org/system/files/sec19-pendlebury.pdf) |
| TESSERACT, MaMaDroid | F1 0.83 | F1 0.32 | **4.0x** | Time split only | same |
| TESSERACT, MaMaDroid vs original setting | F1 0.97 | F1 0.32 | **22.7x** | Time split plus realistic malware prevalence | same |
| Dos and Don'ts, DREBIN sampling bias | miss 3.6% | miss 15.4% | **4.3x** | Both classes re-sourced from one market, removing an origin shortcut | [USENIX Sec 22](https://www.usenix.org/system/files/sec22-arp.pdf) |
| Dos and Don'ts, DREBIN label noise | F1 0.955 | F1 0.727 | **6.1x** | 9.7% of training labels flipped | same |
| Android detector in continuous deployment | F1 0.99 | F1 0.76 after 6 months | **24x** | Forward time, no retraining. FNR averages 38% over 7 years | [USENIX Sec 23](https://www.usenix.org/system/files/usenixsecurity23-chen-yizheng.pdf) |
| LAMDA, LightGBM | FNR 1.74% | FNR 50.51% (near), 64.10% (far) | **29.0x / 36.8x** | Time split at 2 to 3 years and 4 to 11 years | [2505.18551](https://arxiv.org/abs/2505.18551) |
| Five Android detectors, curator changed only | AUT 0.90 | AUT 0.70 | **3.0x** | Only the person who built the dataset changed | [2506.23814](https://arxiv.org/abs/2506.23814) |
| Phishing URL detectors across years | miss 13.7% | miss 43.8% | **3.2x** | Forward time split across four collections | [2606.11471](https://arxiv.org/abs/2606.11471) |
| Cross-dataset NIDS, Random Forest | F1 99.79% | F1 25.76% | **354x** | Different network, different capture, different people | [2402.10974](https://arxiv.org/abs/2402.10974) |
| Real-Vul, DeepWukong | F1 93% | F1 2% | **14.0x** | Curated and partly synthetic benchmark to real code | [2407.03093](https://arxiv.org/abs/2407.03093) |
| Real-Vul, LineVul | F1 90% | F1 2% | **9.8x** | same | same |
| Ten production guardrails, public to private | Qwen3Guard 91.0% | 33.8% | **7.4x** | Held-out private prompts | [2511.22047](https://arxiv.org/abs/2511.22047) |
| Meta SecAlign, AgentDojo to AgentDyn | ASR 1.9% | ASR 8.98% | **4.7x** | New benchmark in a new domain | [2602.03117](https://arxiv.org/abs/2602.03117) |
| **Shadow Commit, general blind** | **miss 3.64%** | **miss 24.2%** | **6.6x** | 8 of 33, 22 attack families, unweighted. Artifact lives in the sibling repo, not this one | `rule-blind-attacks.json` |
| Shadow Commit, round-7 probe | miss 3.64% | miss 35.3% | 9.7x | 119 attacks from 9 model agents across 6 goals under enforced blindness, deliberately weighted onto the two known-open classes | `research/ROUND-7-BLIND.md` |

Verification status of this table: every row's source resolves and its title matches. The 3.2x
phishing row, the 6.1x label-noise row and the 354x cross-dataset NIDS row are marked
`number_verified: no` in `CITATIONS.json`, meaning the figure was not independently requoted. They
bracket the distribution the "we sit in the middle" claim rests on, so treat that claim as holding on
the verified rows and reopen those three before quoting them individually.

Two of these deserve a note because they are not really the same kind of thing. The 354x
cross-dataset NIDS row and the Real-Vul rows are collapses to near-uselessness, where the detector
stops working rather than degrading. Note the Real-Vul ratios are 14.0x and 9.8x in error terms, not
the 46.5x and 45x you get by dividing the F1 values, which is the mistake this table's preamble warns
about and which an earlier draft of it made. Shadow Commit at 35.3% still contains roughly two
thirds of blind attacks, which puts it in the degrading group rather than the collapsing one.

The curator row is worth reading twice. Five Android detectors lost a third of their accuracy when
nothing changed except **who assembled the dataset**. Both datasets covered the same years and both
already satisfied the temporal-consistency constraints. That is the cleanest published measurement
of the effect our round 7 measures: the identity of the person writing the test set is itself a
distribution shift.

---

## 6. Static analysis, and what industry actually tolerates

The reason this family matters is that it contains the only sourced statements of the false positive
rate at which a real organisation stops using a tool.

| Source | The threshold | Denominator |
|---|---|---|
| Google Tricorder, ICSE 2015 | "A rate >= 10% puts the analyzer on probation, and the analysis writer must show progress toward addressing the issue. If the rate goes above 25%, we may decide to turn the analyzer off immediately" | not-useful clicks over (not-useful + please-fix + apply-fix) clicks |
| Google, CACM 2018 | "If the ratio for an analyzer goes above 10%, the Tricorder team disables the analyzer until the author(s) improve it" | same |
| Google Tricorder, by deployment point | "These analyses break the build when they find an issue, so the effective false positive rate must be essentially zero." and separately "We still enforce a very low effective false positive rate here (< 10%)" for code review | reports the developer chose not to act on |
| Coverity, CACM 2010 | "more than 30% easily cause problems. People ignore the tool." and "We aim for below 20% for 'stable' checkers" | reports triaged false by paying customers |

Google's best analysers measure 0 to 3% not-useful in production. Note the denominator: that rate is
computed over developer clicks, roughly 716 please-fix and 48 not-useful a day, out of roughly 93,000
findings a day, most of which are never clicked at all. It is not a precision over everything
surfaced, and this document's queue-precision comparison says so.

**The structural point, and it is the one that carries into positioning.** Google runs two different
false positive budgets for the same tool depending on what the finding does. A finding that breaks
the build must be at essentially zero. A finding that appears as a code review comment may run up to
10%. The tolerable rate is a function of how reversible the action is. That is exactly the shape of
a system that separates a hold from a discard, and it is the strongest precedent found for
publishing those two rates separately rather than as one number.

For scale, the same family on synthetic benchmarks: OWASP Benchmark v1.2 scorecards give FindSecBugs
a 57.74% false positive rate and SonarQube 17.02%; a separate evaluation reports CodeQL at 68.2%,
SonarQube at 94.6% and Semgrep at 74.8%. Seven Java SAST tools score above 80% F1 on OWASP Benchmark
while missing more than 85% of real Java CVEs, which is the same benchmark-to-reality gap as
section 5. Secret scanning, the closest analogue to one of our own rules: GitHub Secret Scanner at
75% precision and 36% recall.

---

## 7. SOC alert triage, and a correction to the number everyone quotes

The closest real-world analogue to holding work for a person. It also contains the most commonly
miscited number in security, so this section is mostly a warning.

The paper is Alahmadi, Axon and Martinovic, "99% False Positives: A Qualitative Study of SOC
Analysts' Perspectives on Security Alarms", USENIX Security 22,
<https://www.usenix.org/system/files/sec22-alahmadi.pdf>. Verified by downloading the PDF.

**The 99% in the title is not a measurement.** It is one interviewee:

> "When describing the overwhelming number of alarms received, B3 quantified it as 99%, stating: 'We
> know 99% of the alarms we generate are false positives, but we still have to look at them.'"

It is a qualitative study, a survey of 20 practitioners and interviews with 21. Anyone citing "99%
of SOC alerts are false positives" as a measured rate is miscing this paper, and this project must
not do it.

The paper then corrects the reading itself, and the correction is the useful part:

> "Participants showed a distinction between what they consider an FP and what they consider to be
> noise or a benign trigger. The former is a metric to describe false alarms due to the tool's low
> performance, while alarms that organizations choose to ignore for a business justification or due
> to how the network or system is configured are benign triggers/noise. [...] When the analyst
> reported a 99% FP rate, this is found to be mostly benign triggers and not necessarily a
> measurement of the performance of the technology itself."

That distinction maps onto our queue precisely and is used in `POSITIONING.md`.

---

## 8. Transactional agents and the safety tax

### Cordon is the direct prior art and its headline is a seen-set number

arXiv [2606.17573](https://arxiv.org/abs/2606.17573), EuroSys 27. Verified against the PDF. All four
numbers this repository's README attributes to it check out: 45/45 intercepted pre-commit, 14/45 for
strategy adapters, 4.17 ms median rollback, and the mediation share stated in the paper as
"22.2-23.4%".

Two things the README does not say and should.

**Its 45 cases were built by its own authors.** The suite is "constructed as the cross product of
nine defense-boundary categories and five transaction-level risk families", and the nine categories
are the boundaries of the baselines it is compared against. There is no blind set anywhere in the
paper. By this repository's own standard, 45/45 is Cordon's 3.64% published without a 35.3% beside
it.

**It does not report a benign human-ask rate.** Table 4 carries an approval-events column reading 0,
45, 36 and 40, but every one of those sits on the 45 risk-bearing workflows where each case is risky
by construction. Table 6, the benign benchmarks, reports task correctness only: tau-bench 87.5% to
90.0% and Terminal-Bench 100.0% to 100.0%, with no approval column. On benign work Cordon measures
whether the task still succeeds, never how often a person was stopped. Terminal-Bench sitting at
100.0% for both arms means that half of the benign check cannot detect a degradation at all.

### The safety tax has a published vocabulary

"Permission Denied", arXiv [2608.02670](https://arxiv.org/abs/2608.02670), 12 coding agents on
Terminal-Bench 2.1 under nested enterprise policy levels. From the abstract: "under the strictest
policy, success losses reach 18.3 points and cost inflation 167.3%, and the two axes disagree; the
model that best preserves success is also the one that loses the most efficiency". This is the
published language for what a policy costs the work, and it is the right frame for our own benign
numbers.

---

## 9. What nobody publishes

Recorded as findings, because for the question this survey exists to answer they are the answer.

1. **No agent defence publishes a human-hold rate on benign traffic as a headline number.** Four
   systems publish something adjacent (RTBAS, AgentArmor, Progent, CaMeL) and only AgentArmor
   measures it on a benchmark its authors did not build. CaMeL measures the right quantity and
   publishes it as a bar chart with no value in text or table.

2. **Nothing corresponds to a benign-destroyed rate.** Across the sources opened in this survey, no
   published agent defence separates irreversible damage to legitimate work from recoverable
   interference. Every paper measures blocking, refusal or utility loss, and none measures damage.
   The vocabulary does not exist in this literature. The one design noted as holding-and-refining
   rather than blocking, Task Shield, is described in a survey of the area as "a valuable design
   reference", meaning it is treated as unusual.

3. **Almost no attack-side paper reports a benign-side number at all.** One adaptive-attack paper
   states the omission outright: "since this paper focuses on evaluating robustness" it does not
   measure the benign side.

4. **Confidence intervals are rare but not absent.** AgentDojo reports 95% intervals in Table 5,
   which is more than most. No source found in this survey reports a cluster-robust interval that
   accounts for its test cases not being independent draws, which is the disclosure
   `research/CLUSTER-INTERVALS.md` makes about our own numbers.
