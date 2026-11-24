#!/usr/bin/env node
// Turns the Playwright JSON report of playwright.journeys.config.ts into the P8-T03 evidence file and
// copies the per-journey PNG screenshots next to it. Used by scripts/lab/journeys.sh --evidence.
//   node scripts/lab/journeys-report.mjs <results.json> <out.json> [--lab 0|1] [--shots <dir>] [--shots-out <dir>]
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

const [input, output, ...rest] = process.argv.slice(2);
if (!input || !output) {
  console.error(
    'usage: journeys-report.mjs <results.json> <out.json> [--lab 0|1] [--shots dir] [--shots-out dir]',
  );
  process.exit(2);
}
const opt = (k) => {
  const i = rest.indexOf(k);
  return i >= 0 ? rest[i + 1] : undefined;
};
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..');
const report = JSON.parse(readFileSync(input, 'utf8'));

const shotsIn = opt('--shots');
const shotsOut = opt('--shots-out');
const copied = new Map();
if (shotsIn && shotsOut && existsSync(shotsIn)) {
  mkdirSync(shotsOut, { recursive: true });
  for (const f of readdirSync(shotsIn).filter((n) => n.endsWith('.png'))) {
    copyFileSync(path.join(shotsIn, f), path.join(shotsOut, f));
    copied.set(f, path.relative(root, path.join(shotsOut, f)));
  }
}

const journeys = [];
const walk = (suite, file) => {
  for (const s of suite.suites ?? []) walk(s, s.file ?? file);
  for (const spec of suite.specs ?? []) {
    for (const t of spec.tests ?? []) {
      const r = t.results?.[t.results.length - 1] ?? {};
      const id =
        /^(J\d\d)\b/.exec(spec.title)?.[1] ?? (t.projectName === 'seed' ? 'seed' : spec.title);
      const status =
        r.status === 'passed'
          ? 'PASS'
          : r.status === 'skipped' || t.status === 'skipped'
            ? 'NOT RUN'
            : 'FAIL';
      const steps = (t.annotations ?? r.annotations ?? [])
        .filter((a) => a.type === 'step')
        .map((a) => JSON.parse(a.description));
      const skip = (t.annotations ?? []).find((a) => a.type === 'skip');
      const shots = (r.attachments ?? [])
        .filter((a) => a.contentType === 'image/png' && copied.has(`${a.name}.png`))
        .map((a) => copied.get(`${a.name}.png`));
      journeys.push({
        id,
        title: spec.title,
        project: t.projectName,
        file: path.join('apps/web/tests/e2e/journeys', spec.file ?? file ?? ''),
        status,
        ...(skip ? { reason: skip.description } : {}),
        durationMs: r.duration ?? 0,
        steps,
        screenshots: shots,
        ...(r.errors?.length
          ? {
              error: r.errors.map((e) =>
                (e.message ?? '').replace(/\u001b\[[0-9;]*m/g, '').slice(0, 600),
              ),
            }
          : {}),
      });
    }
  }
};
for (const s of report.suites ?? []) walk(s, s.file);

const totalBytes = [...copied.values()].reduce((n, p) => n + statSync(path.join(root, p)).size, 0);
const out = {
  ranAt: new Date(report.stats?.startTime ?? Date.now()).toISOString(),
  test: 'P8-T03',
  runner: `scripts/lab/journeys.sh${opt('--lab') === '1' ? ' --lab' : ''}`,
  environment: {
    web: 'apps/web production build (next start :3100), NEXT_PUBLIC_API_MOCK unset',
    api: 'apps/api dist (node dist/main.js :4000), fresh DB ppanel_journeys',
    labAgents: opt('--lab') === '1' ? 'ppanel-lab-node-b (real Go agent)' : 'none',
    playwright: report.config?.version ?? null,
  },
  summary: {
    pass: journeys.filter((j) => j.status === 'PASS').length,
    fail: journeys.filter((j) => j.status === 'FAIL').length,
    notRun: journeys.filter((j) => j.status === 'NOT RUN').length,
    durationMs: Math.round(report.stats?.duration ?? 0),
    screenshotsBytes: totalBytes,
  },
  journeys,
};
writeFileSync(output, JSON.stringify(out, null, 2) + '\n');
console.log(
  `wrote ${output}: ${out.summary.pass} pass, ${out.summary.fail} fail, ${out.summary.notRun} not run`,
);
