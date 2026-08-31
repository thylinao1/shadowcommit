# Which of net-to-exec's three window constants actually decides anything

`net-to-exec` is the highest-volume rule in the registry and a large part of the 80.3 percent of
human asks that three rules generate. It pairs a network source with an execution sink inside a
window described in its own docstring as "five lines, grown until the window holds 400 characters".
Asked why five and why 400, the answer until now was that they looked right.

A cluster sweep replayed all 8,190 corpus scenarios once per setting. `run.sh` reproduces the local
half; the sweep itself is `research/frontier/`.

## What the corpus says

    WINDOW_LINES      1, 2, 3, 5, 8, 12, 20      byte-identical, every column, every value
    MAX_WINDOW_LINES  10, 20, 40, 80             byte-identical
    WINDOW_CHARS      100, 200, 400, 800, 1600   the ONLY one that moves a number

At the shipped setting the corpus gives 117 misses of 3,161, 65 false aborts of 5,000 and 1,207
human asks. `WINDOW_CHARS` at 100 or 200 gives 63 false aborts instead of 65, with misses and human
asks unchanged. Nothing else in the space moves anything at all.

## Why, and it is not dead code

All three constants are read, at `net-to-exec.ts:115` and `:117`:

```ts
let end = Math.min(lines.length, start + WINDOW_LINES);
let text = lines.slice(start, end).join("\n");
while (text.length < WINDOW_CHARS && end < lines.length && end - start < MAX_WINDOW_LINES) {
  end += 1;
  text = lines.slice(start, end).join("\n");
}
```

`WINDOW_LINES` sets where the window STARTS. The loop then grows it until the text reaches
`WINDOW_CHARS`. On any file whose lines are short enough for that loop to run, the window lands in
the same place no matter where it started, and the starting point is erased.

`window-binding.mjs` measures where that stops being true. The copy of `hunksOf` in it is checked
against the shipped function on 19 inputs, including ragged and empty ones, and the script refuses
to print if they disagree.

    line width   WINDOW_LINES=1   =5 (shipped)   =20     what binds
    --------------------------------------------------------------------------
             4             40             40     40     MAX_WINDOW_LINES
             8             40             40     40     MAX_WINDOW_LINES
            16             24             24     24     WINDOW_CHARS
            24             17             17     20     WINDOW_LINES
            40             10             10     20     WINDOW_LINES
            60              7              7     20     WINDOW_LINES
            80              5              5     20     WINDOW_LINES
           100              4              5     20     WINDOW_LINES
           133              3              5     20     WINDOW_LINES
           200              2              5     20     WINDOW_LINES
           400              1              5     20     WINDOW_LINES

Measured to the character: **against any SMALLER value, the shipped 5 starts changing the answer
only once lines exceed 100 characters.** Below that the growth loop reaches 400 on its own and lands
identically.

So the honest description of this rule is not "five lines with a character budget as a guard". It is
**a 400 character budget, with the line count as a floor that only binds on unusually long lines**,
and the docstring has it the wrong way round.

## The part an attacker chooses

The window is not a fixed distance. It is a function of line width, and line width is written by
whoever writes the file.

    lines of   6 chars -> the window spans 40 lines, so source and sink can sit 39 lines apart and still pair
    lines of  18 chars -> 22 lines, so 21 apart
    lines of  40 chars -> 10 lines, so  9 apart
    lines of  80 chars ->  5 lines, so  4 apart
    lines of 200 chars ->  5 lines, so  4 apart

Long lines shrink the window. An attacker who pads each line past 100 characters gets the smallest
window this rule will ever use, and a source and a sink five lines apart stop pairing. That is the
same axis that produced the earlier `net-to-exec` to `cross-effect` dead zone, now measured on the
rule's own terms.

## What the corpus cannot see, which is the finding, and it is now counted

`window-blindness.mjs` runs the shipped `hunksOf` at `WINDOW_LINES` 0, 5 and 1000 over every content
block the corpus feeds `net-to-exec`, and compares the hunk sets block for block.

    content blocks examined                        10,240
    largest block                                  4,132 lines, 147,884 characters
    blocks under 400 chars and 40 lines            6,235 (60.9%)
    hunk set differs at WINDOW_LINES=0    vs 5     639 of 10,240
    hunk set differs at WINDOW_LINES=1000 vs 5     4,005 of 10,240

**The windows change on 4,005 of 10,240 blocks and not one of 8,190 verdicts moves.**

That is the sharpest statement of the corpus's blind spot anyone has produced here. The parameter is
read, it is doing work, it reshapes 39 percent of the windows the rule looks through, and the whole
evaluation returns byte-identical numbers. No attack in the corpus has a source and a sink at a
distance where a window boundary falls between them, so the corpus cannot grade the one thing this
rule is for.

**A correction to my own conclusion, made the same night.** The sweep's report first read a flat axis
as an axis nothing reads, and printed "FLAT AT ITS OWN EXTREME, so nothing in 8,190 scenarios reads
it". That inference does not follow and this measurement is what showed it: flat means the CORPUS
cannot see the axis, and whether the code reads it is a different question the sweep cannot answer.
The report says so now.

That is the third independent arrival at the same conclusion this week, after `cross-effect` deciding
0 of 8,190 rows and the mutation run's `regex-widen` score of 0 killed out of 56. The corpus is good
at whether a rule fires and nearly blind to where its edges are.

## What not to conclude

None of this says the shipped setting is wrong. It says the line count is not doing the work its
docstring claims, that the character budget is the real parameter, and that the distance an attacker
gets is theirs to choose within a factor of eight. Changing `WINDOW_CHARS` to 200 removes two false
aborts on this corpus and costs nothing measurable, but "costs nothing measurable" on a corpus that
cannot see window edges is exactly the sentence to be careful with.
