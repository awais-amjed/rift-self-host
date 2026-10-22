/**
 * Line diffs and three-way merges, for compose files.
 *
 * Its own small module because the image has no `diff` or `git` the console
 * may run, and a compose file is a few hundred lines: a table of common
 * subsequences is instant at that size.
 */

/** A file's lines, without the empty one after its last newline. */
export function splitLines(text: string): string[] {
  return text === "" ? [] : text.replace(/\n$/, "").split("\n");
}

/** One line of an alignment: in both files, only the first, or only the second. */
interface Step {
  mark: " " | "-" | "+";
  text: string;
  /** Its index in the first file; for a `+`, where it would go. */
  before: number;
  /** Its index in the second file; for a `-`, where it would go. */
  after: number;
}

/** [a] turned into [b] with as few lines removed and added as possible. */
function align(a: string[], b: string[]): Step[] {
  const n = a.length;
  const m = b.length;
  // common[i][j]: the longest common subsequence of a[i..] and b[j..].
  const common = new Uint32Array((n + 1) * (m + 1));
  const at = (i: number, j: number) => i * (m + 1) + j;
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      common[at(i, j)] = a[i] === b[j]
        ? common[at(i + 1, j + 1)] + 1
        : Math.max(common[at(i + 1, j)], common[at(i, j + 1)]);
    }
  }

  const steps: Step[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      steps.push({ mark: " ", text: a[i], before: i, after: j });
      i++;
      j++;
    } else if (i < n && (j === m || common[at(i + 1, j)] >= common[at(i, j + 1)])) {
      // What went comes before what replaced it, as in any diff.
      steps.push({ mark: "-", text: a[i], before: i, after: j });
      i++;
    } else {
      steps.push({ mark: "+", text: b[j], before: i, after: j });
      j++;
    }
  }
  return steps;
}

/**
 * The lines that differ between [before] and [after], with [context] lines
 * around each change: `-` for a line only in [before], `+` for one only in
 * [after], and `@@` with the line number in [after] where a stretch begins.
 */
export function lineDiff(before: string, after: string, context = 3): string {
  const steps = align(splitLines(before), splitLines(after));
  const shown = new Set<number>();
  steps.forEach((line, index) => {
    if (line.mark === " ") return;
    for (let k = index - context; k <= index + context; k++) shown.add(k);
  });

  const out: string[] = [];
  let previous = -2;
  steps.forEach((line, index) => {
    if (!shown.has(index)) return;
    if (index !== previous + 1) out.push(`@@ line ${line.after + 1}`);
    out.push(`${line.mark} ${line.text}`);
    previous = index;
  });
  return out.join("\n");
}

/** How many lines [a] and [b] differ by: removed plus added. */
export function changedLines(a: string, b: string): number {
  return align(splitLines(a), splitLines(b)).filter((step) => step.mark !== " ").length;
}

/** What merging found: the merged file, or where the two sides collide. */
export type Merged =
  | { clean: true; text: string }
  /** Line numbers in [ours] where a change of ours meets one of theirs. */
  | { clean: false; conflicts: number[] };

/**
 * [ours] and [theirs] both started from [base]: keep the changes each made,
 * as `git merge` does. Where both changed the same stretch differently there
 * is no right answer, and the merge is not clean.
 */
export function merge3(base: string, ours: string, theirs: string): Merged {
  const b = splitLines(base);
  const o = splitLines(ours);
  const t = splitLines(theirs);
  const inOurs = matches(b, o);
  const inTheirs = matches(b, t);

  const out: string[] = [];
  const conflicts: number[] = [];
  let bi = 0;
  let oi = 0;
  let ti = 0;
  // The stretch up to a line all three share: whichever side changed it
  // wins, and when both did the same, either.
  const settle = (bEnd: number, oEnd: number, tEnd: number) => {
    const was = b.slice(bi, bEnd);
    const mine = o.slice(oi, oEnd);
    const next = t.slice(ti, tEnd);
    if (same(mine, was)) out.push(...next);
    else if (same(next, was) || same(mine, next)) out.push(...mine);
    else conflicts.push(oi + 1);
  };
  for (let k = 0; k < b.length; k++) {
    if (inOurs[k] < 0 || inTheirs[k] < 0) continue;
    settle(k, inOurs[k], inTheirs[k]);
    out.push(b[k]);
    bi = k + 1;
    oi = inOurs[k] + 1;
    ti = inTheirs[k] + 1;
  }
  settle(b.length, o.length, t.length);

  if (conflicts.length > 0) return { clean: false, conflicts };
  return { clean: true, text: out.length === 0 ? "" : out.join("\n") + "\n" };
}

/** For each line of [a], the index of the same line in [b], or -1. */
function matches(a: string[], b: string[]): Int32Array {
  const found = new Int32Array(a.length).fill(-1);
  for (const step of align(a, b)) {
    if (step.mark === " ") found[step.before] = step.after;
  }
  return found;
}

function same(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((line, i) => line === b[i]);
}
