# Research documents: claims about code that no longer match the source

An audit of research/*.md the way the demo driver was audited, but on a different axis: claims
ABOUT CODE, not figures (a separate audit covered figures). 36 documents, one auditor each,
every flagged claim re-checked by a second adversarial pass whose job was to refute it. The
speaking-versus-quoting rule was the top guard, so a dated or pinned record that disagrees with
current code is NOT counted; only a live claim the current source contradicts is.

One sharpening of that rule, from session 91, because the naive form ("archival page, do not touch")
mislabels a class: what matters is what the sentence is FOR, not what page it sits on. A figure that
IS the record (the run's own measured output) stays even when current values have moved past it. A
figure that POINTS AT the current value from inside a record (a note reading "the shipped rate is
now X" in order to say the record below no longer matches it) is a LIVE claim and must track the
current value, because being current is its only job. Fencing it would leave the fence itself wrong.
The `corpus-run.md` refusal in this session's doc pass and 91's TWINS-REPORT corrections came to
opposite conclusions from the same kind of header for exactly this reason.

Numbers: 512 code-claims examined, 443 of them live. 31 confirmed stale after the verify pass, 8
uncheckable without running something. 15 of 36 documents had no stale code-claim at all. Two
load-bearing findings were re-verified by hand before this was written.

Severity: load-bearing = the stale claim justifies a decision or a result; minor = a stale
reference or recommendation that misleads a reader; cosmetic = a line number or identifier drift
where the substantive claim still holds.

## Load-bearing (4)

### research/ROUND-7-BLIND.md:89
**Claim (live):** `node research/round7-goal-intervals.mjs`, which recomputes the union residual from the committed result files rather than reading it off this page.

**References:** research/round7-goal-intervals.mjs ,  the WHICH build selector (shippedMiss vs unionMiss)

**What the source shows:** Re-read research/round7-goal-intervals.mjs:53-58: `const WHICH = process.argv.includes("--union") ? unionMiss : shippedMiss;` ,  the bare command printed at ROUND-7-BLIND.md:89 selects shippedMiss (semantic-only) and labels its output "SHIPPED build, insecure-idiom only". The strongest refutation (that shipped and union coincide numerically) fails on the committed data: at commit f2a14200, git grep counts 42 semantic misses vs union 41 (doc's own expected output, ROUND-7-BLIND.md:140), so the default run yields 42/119=35.3% with a different per-goal split and different intervals than the union table at ROUND-7-BLIND.md:71-87 (41/119=34.5%, Wilson [26.52%,43.36%]). Line 89 is present-tense reproduce prose, not a dated record, and `--union` appears nowhere in the document (grep count 0), so the printed command cannot reproduce the page's union residual as claimed.

### research/ROUND-7-BLIND.md:191
**Claim (live):** Both rules shipped, the union of what they newly contain is 16 of the 57 baseline misses.

**References:** apps/server/src/rules/index.ts ,  the imported/exported rule registry

**What the source shows:** Re-read apps/server/src/rules/index.ts:29-66: 17 imports/entries, insecureIdiomRule at lines 41 and 60 is present but no governance-weakened import exists; no apps/server/src/rules/governance-weakened.ts in HEAD and grep for its rule name "security-control-weakened" finds nothing in src. git merge-base --is-ancestor 21f140d HEAD exits 1 ,  PR #53's commit was never merged (it lives only on pr53-review and submission/lane branches). ROUND-7-BLIND.md:191 "Both rules shipped" is an undated, unpinned present-perfect assertion of shipping status, not a record of a pinned run (the doc's commit pins reference the graded trees, not shipping). The repo's own PROJECT.md:226-228 and research/benchmarking/POSITIONING.md:297 confirm the contradiction: governance-weakened's PR is still open, the union "describes a tree nobody has," and the 34.5% union figure is marked "Do not quote."

### research/corpus/PROBE-AUDIT-TRAIL.md:21
**Claim (live):** `replay-v2.mjs:79` sets `ctx.protectedPaths` to three patterns, `customers.jsonl`, `.env`, `secrets`... So the harness context adds nothing, and no path anywhere in the default harness is protected by way of `ctx` alone. The audit-trail patterns reach the policy only through `buildPolicyContext`, which the replay harness never calls.

**References:** research/corpus/replay-v2.mjs ,  what ctx.protectedPaths is set to when the shipped grading command runs

**What the source shows:** Re-read research/corpus/replay-v2.mjs myself and the auditor is right on every point. Line 79 is inside the build-staleness mtime walk (newestSource loop), not a protectedPaths assignment. The actual protected-set wiring is: line 214 imports DEFAULT_PROTECTED_PATHS directly from the built policy-context.js (the product's full list); line 262 defines LEGACY_3PAT (customers.jsonl / .env / secrets); line 263 sets PROTECTED_DEFAULTS = SHADOW_HARNESS_3PAT==="1" ? LEGACY_3PAT : DEFAULT_PROTECTED_PATHS; line 446 passes protectedPaths: PROTECTED_DEFAULTS into the policy context. So by default the shipped grading command grades against the product's full seven-pattern set, including the audit-trail patterns, and they reach the policy without buildPolicyContext. The comment block at replay-v2.mjs:246-268 explicitly records this as the session-91 fix ("This harness carried THREE patterns ... while production ships SEVEN ... SHADOW_HARNESS_3PAT=1 reproduces the old three-pattern behaviour"). I tried to read the document line as a record and cannot: PROBE-AUDIT-TRAIL.md:18-24 is headed "Read this before you believe a verdict" and asserts in the present tense what "the shipped command" and "the replay harness" do now, with no date, commit pin, or "used to" framing ,  it is a live claim, and each of its three sub-assertions (line number, three-pattern default, buildPolicyContext being the only route) contradicts current source.

### research/mutation/PHASE0-EQUIVALENT-SPLIT.md:21
**Claim (live):** Only `cross-effect.js` changed between the mutated tree `08a6c37` and current `main` (diff of the built `dist/rules/*.js`, every other rule byte-identical) ... so the 339 non-cross-effect survivors are valid on current main.

**References:** apps/server/dist/rules/net-to-exec.js, trojan-source.js, exec-surface.js vs the offsets the doc's own mutant IDs cite

**What the source shows:** Re-verified independently: git diff --stat 08a6c37..main over apps/server/src/rules/*.ts (tests excluded) shows FIVE rules changed, not one ,  cross-effect.ts, net-to-exec.ts (+382 lines, 182→526), exec-surface.ts (+151), insecure-idiom.ts (+199), guard-file.ts (+74) ,  and the current built apps/server/dist/rules/net-to-exec.js contains the post-08a6c37 constants CONSTANT_WORDS/MAX_OPERAND_CHARS/SINK_TOKENS, so it is not byte-identical to the 08a6c37 build. The record defense fails: the claim was true at page creation (285f653, 31 Aug 00:37, when only cross-effect.ts differed), but net-to-exec/exec-surface/guard-file diverged at 3fe5a6f (02:39) and the page was amended AFTER that (105ed44, 07:41) with the unpinned present-tense claim ('current main') left standing, and PHASE0-EQUIVALENT-SPLIT.md:74 reasserts 'only cross-effect diverged, so the non-cross-effect figures hold'. research/mutation/README.md:112-113 itself records that main moved through the net-to-exec precision work since 08a6c37. One caveat on the auditor's evidence: trojan-source.ts did NOT change between 08a6c37 and main, so the trojan-source offset finding is unsound, but the verdict does not depend on it.

## Minor (16)

### research/LEAKAGE-PROOF.md:300
**Claim (live):** `replay-v2.mjs:159`, inside the harness's own context builder: `taskPrompt: scenario.intent === "benign" ? scenario.description : undefined,` ... **The `taskPrompt` line should still be deleted from the harness.** It is dormant, not harmless.

**References:** research/corpus/replay-v2.mjs ,  the harness's taskPrompt construction in buildContext()

**What the source shows:** The claim stands. LEAKAGE-PROOF.md:340 is a LIVE forward-looking recommendation ("The `taskPrompt` line should still be deleted from the harness. It is dormant, not harmless. The next rule that reads a task prompt ... would score free points on this corpus"), not a pinned record ,  the doc's dating disclaimer (lines 10-38) pins only its figures to build 58fa2bce, while the word "still" asserts a present obligation. Current source contradicts both the description and the premise: research/corpus/replay-v2.mjs:159 is no longer the taskPrompt assignment; the context builder now spreads taskPromptFieldFor(scenario) (line 445), whose default mode is "fixture" (line 398: `const TASK_PROMPT_MODE = process.env.HARNESS_TASK_PROMPT ?? "fixture"`), returning the same constant string TASK_PROMPT_FIXTURE (lines 405, 420) on every row regardless of intent ,  so a prompt-reading rule can no longer score free points by field presence. The leaking assignment survives only verbatim inside the opt-in `HARNESS_TASK_PROMPT=label` diagnostic mode (line 413), deliberately kept to reproduce the published baseline byte-for-byte, and the comment block at lines 326-396 (dated MEASURED 2026-08-31) documents four full replays on two policy builds showing 0/8190 decisions differ across the non-leaking modes. The doc's live claim that the leak sits in the harness's default context path, and its standing "delete it" recommendation, are both contradicted by a shipped fix broader than the one recommended. I could not refute the auditor: the section-4 code fence could be read as a quote, but the line-340 bullet is unambiguously a present-tense directive about current code.

### research/LEAKAGE-PROOF.md:484
**Claim (live):** 2. **Delete the `taskPrompt` line from `replay-v2.mjs:159`.** Dormant channel, one line, no cost.

**References:** research/corpus/replay-v2.mjs:159 and the taskPrompt construction it refers to

**What the source shows:** Re-read research/corpus/replay-v2.mjs: line 159 now holds registry-rule wrapping code, not a taskPrompt construction; the leaking expression survives only as the opt-in "label" replay mode at replay-v2.mjs:413 inside taskPromptFieldFor() (line 408), with the default mode "fixture" at line 398 supplying a constant non-leaking string on every row, and the comment at lines ~326-333 explicitly saying the harness "used to" build the field the old way. The claim at research/LEAKAGE-PROOF.md:484 is a LIVE action item, not a record: it sits in the maintained "What would settle it" list whose adjacent item 3 (line 485) is marked "DONE" when completed, so item 2's unmarked state asserts the deletion is still pending and that the line exists at replay-v2.mjs:159. Both assertions contradict current source ,  the channel was remediated by mode-parameterization (fixture default), not deletion, and the code's comment block above line 397 documents why deletion ("none" mode) would grade a context the product never builds. Could not refute the auditor.

### research/METRICS.md:65
**Claim (live):** The script reads that one file, writes nothing, and asserts the nine published headline counts before it computes anything new.

**References:** research/overhead/measure-metrics.mjs ,  the `checks` array asserted against report-metrics.json before computation

**What the source shows:** Re-read research/overhead/measure-metrics.mjs:58-66 myself: the `checks` array has exactly 7 entries (rows, attacks, benign, decidable attacks, miss=true, falseAbort=true, benign held), and no alternative counting reaches nine ,  the ratio() helper at line 57 extracts only numerators, and each ratio's denominator is one of the already-counted corpus entries (attacks_policy_decidable at line 62, benign at line 61), so the distinct asserted values are 7, not 9. The METRICS.md:65 sentence is present-tense, undated, and describes the script's current behavior ("The script reads... and asserts... before it computes anything new"), so it is a LIVE claim, not a record ,  the genuinely recorded material (the falsification runs at lines 68-72) is separately dated ("Re-run today") and does match. The "nine" traces to the script's own stale inline comment (measure-metrics.mjs:42, "These nine numbers used to be literals"), which describes the OLD hardcoded set; the header comment at line 14 says "five", so the code's comments disagree with each other and neither matches the actual 7. I also note the sentence's "reads that one file" is loose ,  the script reads two files, results.jsonl (line 31) and report-metrics.json (line 54) ,  but the flagged mismatch, the count nine, stands: I could not refute it.

### research/METRICS.md:216
**Claim (live):** Four of the fifteen shipped rules never fire at all, which is a statement about the corpus and not about those rules.

**References:** apps/server/src/rules/index.ts ,  export const rules array (the shipped rule registry)

**What the source shows:** Re-read apps/server/src/rules/index.ts:48-66: the exported `rules` array registers 18 rules (re-read 1 September 2026 after `governance-weakened` landed; it was 17 when this audit first ran, and the claim being audited said fifteen, so the finding stands and only the source figure moved), including crossEffectRule (line 63) and readExposureRule (line 64); the built dist/rules/index.js confirms 17 (names include cross-effect-composition and protected-read-exposure). METRICS.md:216 ("Four of the fifteen shipped rules never fire at all") is present-tense prose, not a dated or fenced record, and is repeated as live conclusion 5 at METRICS.md:665. The repo itself confirms the drift: research/overhead/measure-metrics.mjs:239-243 documents that the hand-maintained list "was missing cross-effect and carried capability-grant... a document said fifteen where another said sixteen," and its own REGISTRY (lines 246-251) lists 16 modules, still missing read-exposure versus the 17-rule built registry. "Fifteen" cannot be reconciled with the current shipped registry.

### research/METRICS.md:665
**Claim (live):** Four of the fifteen shipped rules never fire here. `multi-file-delete`, `symlink-escape`, `platform-secrets` and `outbound-provenance` contribute nothing to any curve above.

**References:** apps/server/src/rules/index.ts ,  export const rules array (the shipped rule registry)

**What the source shows:** The count is live and wrong: apps/server/src/rules/index.ts:48-66 exports 18 rules (re-read 1 September 2026 after `governance-weakened` landed; it was 17 when this audit first ran, so the audited claim of fifteen is still wrong and only the source figure moved) (crossEffectRule at line 63 and readExposureRule at line 64 included, per the file's own header describing "Position 16 ... read-exposure"), while METRICS.md:665 says "the fifteen shipped rules" in present tense with no date/commit pin on the line. The record defense fails for the count: git shows both rule-adding commits (5fd1d3a "the sixteen rules", a247627 adding cross-effect.ts/read-exposure.ts) are ancestors of 979c58f, the last commit touching research/METRICS.md, so the doc was edited after the registry reached 17 and the wording is stale prose, not a preserved snapshot. However, the other half of the sentence ,  the four named rules "contribute nothing to any curve above" ,  is a true record of the sha256-pinned 2026-08-30 replay and is explicitly disclaimed at METRICS.md:216 as "a statement about the corpus and not about those rules"; only the "fifteen shipped" registry count fails.

### research/OVERHEAD.md:60
**Claim (live):** the committed demo pack carries twelve `seal.fallback` records across seven step files, five distinct run ids, and no `seal.mounted` anywhere in `evidence/`... $ grep -ho '"kind": "seal\.fallback"' evidence/demo-run/steps/*.json | wc -l
12

**References:** evidence/demo-run/steps/*.json ,  count of "kind": "seal.fallback" occurrences

**What the source shows:** Re-ran the doc's own command and an independent JSON-aware count: evidence/demo-run/steps/*.json now contains 13 "kind": "seal.fallback" matches (03-turn-1-normal.json:35 and :347 are the file whose count grew from 1 to 2), not the twelve asserted at research/OVERHEAD.md:60 and shown as the fence's expected output at OVERHEAD.md:63-64. The line is a live claim, not a record: it is unqualified present tense with no date or commit pin, and OVERHEAD.md:61 explicitly frames it as "checkable without trusting either page". The claim was accurate at 9600c9b (OVERHEAD.md's last-touch commit ,  git show 9600c9b totals exactly 12) but the pack was regenerated after the doc in commits 42a5a4a/8645fba/7eb1598, so the current source contradicts it by one. The sentence's other parts (seven step files, five distinct run ids per 10-platform-after.json:6,94,189,304,397, no seal.mounted in evidence/) still hold.

### research/PROVENANCE-FLOOR.md:78
**Claim (live):** It is still bounded by everything else: the destination must be on the allowlist, the call is recorded in the broker's decision log with its host and path, and a write-like call is held regardless of size.

**References:** apps/server/broker/server.mjs write-like handling path (the `hold`/DENY branching after `classifyCall`)

**What the source shows:** Re-read confirms the auditor. apps/server/broker/server.mjs:32 sets MAX_BODY_BYTES = 8*1024*1024; collect() at server.mjs:289-296 sets truncated=true once the body exceeds that cap; and on the write-like path, server.mjs:506-510 checks `if (truncated)` and responds decision:"DENY", reason:"payload-exceeds-hold-limit" (HTTP 413), returning before the `hold(...)` call at server.mjs:514. So a write-like call over 8MB is denied outright, never held ,  the live claim "a write-like call is held regardless of size" is literally contradicted by current source. Refutation attempts fail: the sentence is in "The honest statement" section of research/PROVENANCE-FLOOR.md (line 78), present-tense, undated, asserting current broker behavior ,  not a record or quote. The one softening reading ("regardless of size" meaning no size escapes broker control) does not rescue the word "held": above 8MB the mechanism is a 413 deny, not a hold. Note the security conclusion the sentence supports still holds ,  a denied write is contained at least as strictly as a held one ,  so the defect is in the described mechanism, not the bound.

### research/benchmarking/SECRET-SCAN-DIAGNOSIS.md:44
**Claim (live):** Downgrade the keyword arm from `discard` to `review`. ... A keyword-adjacency guess is not format-certain. It is the weakest evidence the rule produces and it is the only weak arm sitting at `discard`.

**References:** secret-scan.ts KEYWORD_ASSIGNMENT match handling ,  decision value assigned to keyword-arm findings

**What the source shows:** Re-read apps/server/src/rules/secret-scan.ts: line 211 pushes the keyword-arm finding with decision "review" (comment: "`review`, not `discard`") and line 223 does the same for the decoded-keyword path; only the format arms (lines 193/197/202/216/260) use "discard". The doc's present-tense claim at research/benchmarking/SECRET-SCAN-DIAGNOSIS.md:44 that the keyword arm "is the only weak arm sitting at `discard`" therefore contradicts current source. I could not refute it as a record: the sentence is the doc's own unpinned, undated, present-tense assertion (the nearby blockquote of the code docstring is separate), and the doc carries no "applied/superseded" marker. Git confirms the staleness mechanism: doc last committed at dc6ded3 (2026-08-31 19:56:44), fix landed at b8bb89d (20:02:29, "the keyword arm is a guess, and now it says so"), which is an ancestor of HEAD 368d1d5 ,  i.e., the doc's recommendation has already shipped and its premise is stale, not wrong at time of writing.

### research/corpus/PROBE-AUDIT-TRAIL.md:37
**Claim (live):** The customers pair discards under the shipped harness; the journal twins commit with rule `none`.

**References:** apps/server/dist/rules/protected-identity.js protectedIdentityRule.run, given the shipped harness's default ctx.protectedPaths

**What the source shows:** Re-read research/corpus/PROBE-AUDIT-TRAIL.md:36-37 ,  present-tense, undated claim about "the shipped harness". Current research/corpus/replay-v2.mjs:263 defaults PROTECTED_DEFAULTS to the product's DEFAULT_PROTECTED_PATHS (7 patterns incl. the journal pattern at apps/server/dist/policy-context.js:45) and passes it as ctx.protectedPaths at replay-v2.mjs:446; the doc's described three-pattern set is now the retired SHADOW_HARNESS_3PAT=1 escape hatch. Directly invoking protectedIdentityRule.run (apps/server/dist/rules/protected-identity.js:23-38) on write/delete effects for data/journal.jsonl with that default returns protected-asset-delete/protected-asset-write, both decision "discard" ,  the journal twins no longer commit with rule none. Doc written at b85b2a3, harness changed later in bc7c6b4 (b85b2a3 is its ancestor), doc never updated.

### research/corpus/README.md:15
**Claim (live):** That is `setup.sh` (pin the four benign sources) followed by `check.sh` (the eight stages below).

**References:** research/corpus/check.sh stage count

**What the source shows:** README.md:15 is a live claim ("the eight stages below") about what check.sh runs now, but research/corpus/check.sh currently announces stages 1-11 plus 2b and 8b (check.sh:19,23,31,46,49,52,55,58,62,77,96,143,154), and its own comments call 9/10/11 "stages" (check.sh:118,130,161). No eight-item stage list exists below in the README either ,  the "Run one stage at a time" section (README.md:105-119) lists nine commands and omits stages 9-11. Refutation attempts (that "below" resolves to an eight-item grouping, or that 9-11 are gates rather than stages) both fail against the source.

### research/frontier/README.md:38
**Claim (live):** Nine `cross-effect` settings, which must NOT differ, because that rule decides 0 of 8,190 corpus rows.

**References:** research/frontier/gen-frontier-settings.mjs AXES list (cross-effect: MAX_HITS, MIN_IDENTIFIER, MAX_TAINT_PASSES) and its `shipped()` helper, read against apps/server/dist/rules/cross-effect.js

**What the source shows:** I re-read every cited source and could not refute the auditor. (1) apps/server/dist/rules/cross-effect.js:112-114 declares only `taintPassesFor(modelCount)`, `const MAX_HITS = 4;` and `const MIN_IDENTIFIER = 3;` ,  no `const MAX_TAINT_PASSES = <digits>;` anywhere (same in src/rules/cross-effect.ts:118-120; git show a247627 confirms line `const MAX_TAINT_PASSES = 16;` was replaced by taintPassesFor). (2) gen-frontier-settings.mjs:53-55 still lists MAX_TAINT_PASSES as a cross-effect axis, and shipped() at lines 24-29 throws `no declaration of MAX_TAINT_PASSES` when its regex misses ,  the axis-tripwire loop (line ~99: `const base = shipped(axis.file, axis.name)`) hits that throw before writeFileSync, so the generator crashes and produces zero settings against the current dist. (3) The refutation attempts fail: the README line (research/frontier/README.md:38-41, "Controls. Nine cross-effect settings, which must NOT differ...") is present tense, carries no date or commit pin, and sits in a README whose "Running it" section (README.md:14-16) instructs running the generator against apps/server/dist right now ,  so the design half of the sentence is a LIVE claim about the harness, not a record. The adjacent "None moved" is a record of the completed run and is not the failing part. Timing confirms the drift: README last touched in 5e5691c (2026-08-31 00:32), constant removed in a247627 (2026-08-31 15:53) the same day, with no follow-up to the frontier files; research/corpus/check-constants.mjs:17 (defect C) documents the replacement. Today the harness cannot carry nine cross-effect controls ,  it cannot even emit a manifest.

### research/net-to-exec/WINDOW-BINDING.md:8
**Claim (live):** `run.sh` reproduces the local half; the sweep itself is `research/frontier/`.

**References:** a script named run.sh, claimed to reproduce the local half of the sweep described in research/net-to-exec/ and research/frontier/

**What the source shows:** Re-read research/net-to-exec/WINDOW-BINDING.md:7-8: "`run.sh` reproduces the local half; the sweep itself is `research/frontier/`" is a present-tense, undated reproduction instruction ,  a LIVE claim. No run.sh exists under research/net-to-exec/ or research/frontier/ (ls confirms only .mjs/.md/.sbatch/results files), git log --all --name-status -- '*run.sh' shows the only run.sh ever committed is the unrelated research/benign-realism/run.sh (never one in these lanes, so nothing was deleted after writing), and research/frontier/README.md's "Running it" section documents three node invocations (gen-frontier-settings.mjs, frontier-worker.mjs, frontier-report.mjs) as the actual reproduction path. The named script does not and never did exist; the claim contradicts current source.

### research/realworld-prior/REPORT.md:587
**Claim (live):** Eight harnesses in this repository carry a private copy with seven, missing `registry.yarnpkg.com`, `static.crates.io` and `sum.golang.org`... The last two are fixed here... The other six predate that and belong to other lanes.

**References:** the 8 files listed at lines 592-596: research/corpus/replay-v2.mjs:129, research/corpus/lib/variants.mjs:135, research/queue/probe.mjs:41, research/realworld-prior/replay-real.ts:43, research/queue/instrument.mjs:50, research/queue/narrowing-measure.ts:27, research/benchmarking/exec-probe.ts:53, research/realworld-prior/why-destroyed.ts:41

**What the source shows:** The claim is a live, undated, present-tense assertion ("Eight harnesses in this repository carry a private copy with seven... The other six predate that and belong to other lanes", research/realworld-prior/REPORT.md:586-596) and the current source contradicts it for all eight files: research/corpus/replay-v2.mjs:214,235 imports DEFAULT_REGISTRY_ALLOWLIST from the built policy-context (its comment at 222-227 says the seven-host copy "used to be" there); research/corpus/lib/variants.mjs:133-138 shows the local copy deleted as dead code; research/queue/probe.mjs:118, research/queue/instrument.mjs:56, research/queue/narrowing-measure.ts:21, research/benchmarking/exec-probe.ts:4, research/realworld-prior/why-destroyed.ts:5, and research/realworld-prior/replay-real.ts:36,58 all import the constant. No file carries a private 7-host copy. The record-vs-claim defense fails because the sentence carries no date/pin and explicitly scopes only two fixes to the report itself while asserting the other six remain stale now.

### research/realworld-prior/REPORT.md:1355
**Claim (live):** `research/semantic-judge/payload.ts:104` builds the body from `e.addedLines` alone. `before` and `after` exist on the interface at lines 72 and 73 and are never read. A deletion of a security control is not in the payload at all.

**References:** research/semantic-judge/payload.ts, PayloadEffect.before/after and buildPayload

**What the source shows:** Re-read research/semantic-judge/payload.ts in full: PayloadEffect.before/after are at lines 103-104 and ARE read ,  line 138 computes maskSecrets(removedLinesBetween(e.before ?? null, e.after ?? ""), platformSecrets), and lines 150-161 fold removals into the body as a REMOVED section (pure deletions render as "ADDED:\n(nothing)\nREMOVED:..."), incrementing filesWithRemovals; unrepresentable changes get a CANNOT-CARRY marker. So a deletion of a security control IS in the payload. The claim at research/realworld-prior/REPORT.md:1354-1356 ("builds the body from e.addedLines alone... before and after... are never read... A deletion of a security control is not in the payload at all") is present-tense, cites file:line, and carries no date/commit pin or quoted-earlier-version framing (the report's quoting device appears only in the next subsection at line 1359), so it is a LIVE claim, and its own drifted line cites (72/73 vs actual 103-104) confirm the file changed under it. Git confirms the removal-carrying code is the current (uncommitted working-tree) source; the committed version lacks it, but the audit target is current source. Could not refute: the auditor read both the claim and the code correctly.

### research/secret-scan/MIN-KEYWORD-VALUE.md:95
**Claim (live):** The collapsed form the scanner matches keeps the surrounding quote and comma, so a version pattern anchored without them matches nothing in a real manifest.

**References:** apps/server/src/rules/normalise.ts: collapseKeyValues() / QUOTED_PAIR regex

**What the source shows:** Re-read apps/server/src/rules/normalise.ts:68-71 and 87-93: the QUOTED_PAIR replacement re-inserts only before+key+'='+value, consuming both value quotes. Ran the built export: collapseKeyValues('        "js-tokens": "^4.0.0",') returns '        js-tokens=^4.0.0,' and the KEYWORD_ASSIGNMENT value the guard tests (secret-scan.ts:206-212; PROPOSED.ts:147) is '^4.0.0,' ,  comma kept, quotes gone. The doc line (MIN-KEYWORD-VALUE.md:95) and its twin comment (research/secret-scan/secret-scan.PROPOSED.ts:140-141) are present-tense live claims, not dated records, and the quote half is contradicted; only the comma half is true.

### research/semantic-judge/RESULTS.md:31
**Claim (live):** **One risk this opens, which is recorded here because the wrapper has not been written yet.** ... The mitigations proposed to the wiring lane are to mark model-requested reconsiderations distinctly, keep the deterministic reason primary, label the tier's text as derived from the diff under review, and rate-limit the move so a flooding attempt is visible.

**References:** the semantic-judge composition wrapper (discard->review reconsideration mitigations)

**What the source shows:** RESULTS.md:31 asserts in undated present tense that "the wrapper has not been written yet" and that the four mitigations are merely "proposed to the wiring lane" ,  a live claim, not a pinned record. I re-read research/semantic-judge/wrapper.ts in full: it exists at HEAD and implements all four mitigations ,  SEMANTIC_RECONSIDER_RULE marks model-requested reconsiderations distinctly (wrapper.ts:95, 175, 188), the deterministic reason stays primary via `rule: base.rule` (wrapper.ts:186), quoteUntrusted labels the text "model read of the diff under review, untrusted" (wrapper.ts:104), and reconsiderBudget/granted/onReconsiderBurst rate-limit the move and surface bursts (wrapper.ts:87, 89, 112, 168-180). git log --follow confirms wrapper.ts was created in e38f75e at 2026-08-31 20:18:57 (moved in 8af17c4), 10 minutes after RESULTS.md's last edit b4d24a4 at 20:08:20, and RESULTS.md was never updated. The sentence carries no date, commit pin, or record marker, so it is a stale live claim the current source contradicts.

## Cosmetic (11)

### research/CLUSTER-INTERVALS.md:306
**Claim (live):** `research/METRICS.md` limitation 8 currently ends "the real intervals are wider than the printed ones"

**References:** research/METRICS.md, limitation 8 (item 8 in the Limitations section)

**What the source shows:** Re-read research/METRICS.md:683-686: limitation 8 reads '8. **The Wilson intervals assume independent draws and these rows are not independent.** ... the real intervals are wider than the printed ones. The intervals are in section 1 because they bound sampling noise, not corpus design.' So the item does not end with the quoted phrase; a final sentence follows. I tried to refute this three ways and failed: (1) the line at research/CLUSTER-INTERVALS.md:306-308 says 'currently ends', which is a live present-tense claim about the document's state, not a dated record; (2) git history (commit 1ff921c, which created research/METRICS.md, and git log -S) shows the trailing 'intervals are in section 1' sentence has been part of limitation 8 since the file's creation ,  there was never a version that ended at the quoted phrase, so this is not a record of an older state; (3) the quoted phrase does appear verbatim mid-item (METRICS.md:685) and does end its own sentence, but 'ends' as written is still wrong about the item as a whole. The mismatch is real but purely locational: the substantive point (limitation 8 asserts wider-than-printed without quantification, and can now cite 3.2x/4.0x) is accurate and unaffected, since the trailing sentence is about placement, not magnitude.

### research/LEAKAGE-PROOF.md:68
**Claim (live):** Section 0 lifts the `grade()` function out of `research/corpus/replay-v2.mjs:205` by brace matching and rebuilds it

**References:** grade() function definition in research/corpus/replay-v2.mjs

**What the source shows:** Re-read research/corpus/replay-v2.mjs: grade() is defined at line 491 (grep "function grade" → 491 only), while lines ~200-210 hold a POLICY_PATH/addedLinesBetween comment block. So the ":205" in LEAKAGE-PROOF.md:68 no longer points at grade(). The rest of the sentence remains true of current source: research/overhead/measure-leakage.mjs:118-137 lifts by name (src.indexOf("function grade(")) and brace matching, never by line number, and line 137 is `const grade = liftFunction(REPLAY, "grade")`. The doc's header pin to build 58fa2bce arguably dates the annotation, but the sentence is present-tense mechanism description, so the stale line-number suffix stands as a (trivial) mismatch.

### research/LEAKAGE-PROOF.md:180
**Claim (live):** The grader credits a `review` on an attack whether the control wanted `review` or `discard` (`replay-v2.mjs:216`, `contained && (expected === decision || expected === "discard")`)

**References:** grade()'s `correct` computation in research/corpus/replay-v2.mjs

**What the source shows:** The behavioral claim is correct against current source: research/corpus/replay-v2.mjs:502 reads `correct: contained && (scenario.expected === decision || scenario.expected === "discard"),` inside grade(), with `contained = decision === "discard" || decision === "review"` (line 500) ,  exactly the crediting rule the document describes. But the cited location `replay-v2.mjs:216` is stale: line 216 currently holds `console.error(` in the addedLinesBetween fail-closed guard (re-read replay-v2.mjs:214-218). The pointer is a live reference (no commit pin or date), so the drift is real ,  yet it is purely a line-number displacement caused by an inserted docblock; the quoted clause matches source verbatim and the analysis built on it is unaffected.

### research/LEAKAGE-PROOF.md:200
**Claim (live):** What the policy actually receives is fixed at `replay-v2.mjs:172`: `toEffects()` builds each effect from `path`, `kind`, `mode`, `target`, `escapes`, `bytes`, the outbound fields, `highEntropy`, `effectClass`, and a derived `canonicalPath`, and nothing else.

**References:** toEffects() function in research/corpus/replay-v2.mjs

**What the source shows:** Re-read research/corpus/replay-v2.mjs: toEffects() is defined at line 456 (confirmed by reading lines 450-480), while line 172 holds rule-instrumentation code (`const hits = await inner(effects, ctx);`, read via lines 160-185). The document's line pin at LEAKAGE-PROOF.md:200 is therefore stale. However, the substantive content of the claim ,  that toEffects() builds each effect from path, kind, mode, target, escapes, bytes, the outbound fields (method/host/port/urlPath/provenance/secretPattern), highEntropy, effectClass, and a derived canonicalPath, and nothing else ,  matches the function body at replay-v2.mjs:456-476 exactly. Only the ":172" citation contradicts current source; the field-list assertion the leakage argument depends on is correct.

### research/LIMITATIONS-PLAN.md:49
**Claim (live):** **5. Two known scanner boundaries an attacker can cross for free.** `MAX_LINES = 5000` in `cross-effect.ts` and `net-to-exec.ts`: moving a payload one line down in a created file turns a discard into a commit.

**References:** the constant name MAX_LINES=5000 in apps/server/src/rules/cross-effect.ts and apps/server/src/rules/net-to-exec.ts

**What the source shows:** Re-read apps/server/src/rules/cross-effect.ts:97, which declares `const MAX_LINES_PER_FILE = 5000;` (used at lines 441, 641, 660), not `MAX_LINES`; the backticked identifier only exists in net-to-exec.ts:68 (`const MAX_LINES = 5000;`, used at line 465). The value, the two files, and the described truncation behavior are all accurate, so only the identifier name in cross-effect.ts is wrong.

### research/OVERHEAD.md:119
**Claim (live):** shrinks capture to the upper layer (`captureEffects`, `capture.ts:270`)

**References:** apps/server/src/capture.ts ,  location of `export async function captureEffects`

**What the source shows:** Re-read apps/server/src/capture.ts: `export async function captureEffects` is at line 285 (grep -n confirmed), and line 270 is `export interface CaptureInput {` ,  the :270 locator is wrong. No pin rescues it: the sentence's "at 2c95041" attaches to transactional-runner.ts:837, and even at commit 2c95041 the function was at line 268 (git show 2c95041:apps/server/src/capture.ts | grep -n), so :270 never matched that pin either. But the behavioral half of the claim is TRUE in current source: capture.ts:287 (`mechanism === "overlay" ? "upper" : "merged"`) shows overlay capture walks only the upper layer, exactly as asserted. Only the line number is stale.

### research/ROUND-6-RECONCILE.md:18
**Claim (live):** `security-regression` states its contract in one sentence, the `summary` field of the rule object (`apps/server/src/rules/insecure-idiom.ts:408`)

**References:** apps/server/src/rules/insecure-idiom.ts:408, the `summary` field of the `rule` object

**What the source shows:** Re-read apps/server/src/rules/insecure-idiom.ts: line 408 is `.filter((line) => ASSERTION.test(line))` inside findRemovedAssertions (406-415), while `export const rule` starts at line 425 and its `summary:` field is at lines 427-428. The doc's citation `insecure-idiom.ts:408` is a live pointer with no commit pin or date, so it does contradict current source. But the substantive claim is fully correct: the summary field is the rule's one-sentence contract and the doc's blockquote matches lines 427-428 verbatim. Only the line number drifted (the file grew above the rule export); nothing the document argues from this claim changes.

### research/corpus-v2/TWINS-REPORT.md:79
**Claim (live):** in this tree: `VALUE_PLACEHOLDER` in `apps/server/src/rules/secret-scan.ts` line 76 lists `change_me` and does not list `replace_me` or `set_in_ci`, so the allowlist gap described there is real and still open on 30 August 2026

**References:** VALUE_PLACEHOLDER constant, apps/server/src/rules/secret-scan.ts

**What the source shows:** The locator is genuinely wrong in the current tree: VALUE_PLACEHOLDER is declared at apps/server/src/rules/secret-scan.ts:99-100 (line 76 is inside the docstring added by commit b8bb89d, which the report postdates ,  report committed 31 Aug 20:18, docstring 20:02; even pre-shift it was line 75, not 76). But every substantive assertion holds against current source: the regex at line 99-100 lists change_me and grep confirms replace_me and set_in_ci appear nowhere in the file, so the allowlist gap is real and open exactly as claimed.

### research/corpus/PHASE2-EGRESS.md:22
**Claim (live):** `replay-v2.mjs` `toEffects` carries `method`, `host`, `port`, `urlPath`, `provenance`, `secretPattern` and `highEntropy`. It does, at `:182-185`.

**References:** toEffects() in research/corpus/replay-v2.mjs, cited at lines 182-185

**What the source shows:** Re-read research/corpus/replay-v2.mjs: toEffects is defined at line 456, carries method/host/port/urlPath/provenance/secretPattern via the field loop at line 468 and highEntropy at line 471 ,  the behavioral claim is true. But the doc's pin ':182-185' (PHASE2-EGRESS.md:22) points at the '// ---- PolicyContext construction' comment block and fixture constants (replay-v2.mjs:181-185), not toEffects. The line is present-tense and undated, so it is a live claim with a stale location citation.

### research/frontier/README.md:23
**Claim (live):** The four counts use the SAME predicates as the shipped report (`report.mjs` lines 33 to 67): attack or benign by `intent`, attacks counted only when `policyDecidable`, and `miss`, `falseAbort` and `humanAsk` read from fields the replay sets.

**References:** research/corpus/report.mjs (the 'shipped report' per check-stamp.mjs's own use of that phrase) lines 33-67

**What the source shows:** Re-read research/corpus/report.mjs: intent at :34-35, policyDecidable at :36, miss at :43/:62, falseAbort at :66-67 are inside the cited 33-67 span, but r.humanAsk is read only at report.mjs:68 and :71, outside it ,  so the cited range does not cover one of the four predicates. The substantive claim (same predicates as the shipped report) is verified true against frontier-worker.mjs:53-61, which uses identical intent/policyDecidable/falseAbort/humanAsk predicates; only the line-range citation is off.

### research/net-to-exec/WINDOW-BINDING.md:23
**Claim (live):** All three constants are read, at `net-to-exec.ts:115` and `:117`:

**References:** apps/server/src/rules/net-to-exec.ts ,  the lines where WINDOW_LINES, WINDOW_CHARS and MAX_WINDOW_LINES are read inside hunksOf

**What the source shows:** Re-read apps/server/src/rules/net-to-exec.ts: lines 115 and 117 are inside the Sink interface JSDoc comment (Makefile/postinstall prose), while the actual constant reads are at net-to-exec.ts:336 (WINDOW_LINES) and :338 (WINDOW_CHARS, MAX_WINDOW_LINES) inside hunksOf (starts line 333). WINDOW-BINDING.md:23 is a live claim (no commit pin or date), so the :115/:117 citation contradicts current source. However, the code block the doc quotes matches current lines 336-341 verbatim, so the substantive claim ,  all three constants are read, the code is not dead ,  is true; only the line numbers drifted.

## Uncheckable without a run (8)

These are live claims about code behavior that a read cannot settle; they need the script run,
the test executed, or the artifact regenerated. Listed so they are not mistaken for clean.

- **research/CLUSTER-INTERVALS.md:11** It takes about half a second, writes only to stdout, and takes `--json PATH` to dump every figure.
- **research/METRICS.md:71** Re-run today the same mutation prints `DRIFT: miss=true is 114, the published report says 115.` and exit 1, and the unmodified copy still exits 0.
- **research/OVERHEAD.md:366** Revert-proof: with the production change reverted and the tests kept, the read-count test fails `expected 5 to be 1` and the snapshot test fails because the rea
- **research/benchmarking/POSITIONING.md:431** `verify7-judgements.json` is 57 rows of {id, verdict, correct_action, reason} with no reviewer identity on any row
- **research/corpus/PROBE-COMMENT-MARKERS.md:73** A comparison that cannot fail is not evidence, and this one now carries a self-test that tampers with a row and confirms the check sees it.
- **research/corpus/README.md:158** Only two of the eight are exempt by their own text, because the gate's self-evident list is literal: it holds EXAMPLE and LOOKSLIKEONE and nothing else.
- **research/frontier/README.md:58** the rule's docstring has its two constants the wrong way round
- **research/mutation/PHASE0-EQUIVALENT-SPLIT.md:65** The 373 cross-effect survivors ... The module changed on current main (the distance fix, 63 diff lines)

