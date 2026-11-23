/**
 * Minimal line diff utilities: produce and parse unified diffs. Used for the local draft preview
 * (before a revision is created) and to render the Center's `files[].diff` text. No dependency.
 */

type Op = { t: 'ctx' | 'add' | 'del'; text: string; a: number; b: number };

function splitLines(s: string): string[] {
  if (s === '') return [];
  const lines = s.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** LCS-based edit script. Inputs are capped by the caller (nginx files are small). */
function editScript(a: string[], b: string[]): Op[] {
  const n = a.length;
  const m = b.length;
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ t: 'ctx', text: a[i]!, a: i + 1, b: j + 1 });
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      ops.push({ t: 'del', text: a[i]!, a: i + 1, b: j });
      i++;
    } else {
      ops.push({ t: 'add', text: b[j]!, a: i, b: j + 1 });
      j++;
    }
  }
  for (; i < n; i++) ops.push({ t: 'del', text: a[i]!, a: i + 1, b: j });
  for (; j < m; j++) ops.push({ t: 'add', text: b[j]!, a: i, b: j + 1 });
  return ops;
}

/** Unified diff (`--- a/path` / `+++ b/path` / `@@ -l,s +l,s @@`). Empty string when identical. */
export function unifiedDiff(
  path: string,
  before: string | null,
  after: string,
  context = 3,
): string {
  const a = splitLines(before ?? '');
  const b = splitLines(after);
  const ops = editScript(a, b);
  if (!ops.some((o) => o.t !== 'ctx')) return '';
  const out = [`--- ${before === null ? '/dev/null' : `a${path}`}`, `+++ b${path}`];
  let k = 0;
  while (k < ops.length) {
    while (k < ops.length && ops[k]!.t === 'ctx') k++;
    if (k >= ops.length) break;
    const start = Math.max(0, k - context);
    let end = k;
    // extend hunk while changes are within 2*context of each other
    for (;;) {
      while (end < ops.length && ops[end]!.t !== 'ctx') end++;
      let next = end;
      while (next < ops.length && ops[next]!.t === 'ctx') next++;
      if (next < ops.length && next - end <= context * 2) {
        end = next;
        continue;
      }
      end = Math.min(ops.length, end + context);
      break;
    }
    const hunk = ops.slice(start, end);
    const aLines = hunk.filter((o) => o.t !== 'add');
    const bLines = hunk.filter((o) => o.t !== 'del');
    const aStart = aLines.length ? aLines[0]!.a : (hunk[0]?.a ?? 0);
    const bStart = bLines.length ? bLines[0]!.b : (hunk[0]?.b ?? 0);
    out.push(`@@ -${aStart},${aLines.length} +${bStart},${bLines.length} @@`);
    for (const o of hunk) out.push(`${o.t === 'add' ? '+' : o.t === 'del' ? '-' : ' '}${o.text}`);
    k = end;
  }
  return out.join('\n') + '\n';
}

export type DiffLineType = 'add' | 'del' | 'ctx' | 'hunk' | 'meta';
export interface DiffLine {
  type: DiffLineType;
  oldNo: number | null;
  newNo: number | null;
  text: string;
}

/** Parse unified diff text into display rows with old/new line numbers. */
export function parseUnifiedDiff(text: string): DiffLine[] {
  const rows: DiffLine[] = [];
  let o = 0;
  let n = 0;
  for (const raw of splitLines(text)) {
    if (raw.startsWith('--- ') || raw.startsWith('+++ ') || raw.startsWith('diff ')) {
      rows.push({ type: 'meta', oldNo: null, newNo: null, text: raw });
      continue;
    }
    const h = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (h) {
      o = Number(h[1]);
      n = Number(h[2]);
      rows.push({ type: 'hunk', oldNo: null, newNo: null, text: raw });
      continue;
    }
    if (raw.startsWith('\\')) {
      rows.push({ type: 'meta', oldNo: null, newNo: null, text: raw });
      continue;
    }
    if (raw.startsWith('+')) {
      rows.push({ type: 'add', oldNo: null, newNo: n || 1, text: raw.slice(1) });
      n++;
    } else if (raw.startsWith('-')) {
      rows.push({ type: 'del', oldNo: o || 1, newNo: null, text: raw.slice(1) });
      o++;
    } else {
      rows.push({ type: 'ctx', oldNo: o, newNo: n, text: raw.slice(1) });
      o++;
      n++;
    }
  }
  return rows;
}

export function diffStats(text: string): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of parseUnifiedDiff(text)) {
    if (l.type === 'add') added++;
    else if (l.type === 'del') removed++;
  }
  return { added, removed };
}
