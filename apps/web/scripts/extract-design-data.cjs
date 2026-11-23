// Extracts prototype mock data + EN/TH strings from design/W3 Server Panel.dc.html into dump.json.
// Usage: node scripts/extract-design-data.cjs "../../design/W3 Server Panel.dc.html"  (then regenerate src/mocks/design-data.ts)
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8').split('\n');
const body = src.slice(1332, 1499).join('\n');
const last = src[1499];
const pairs = [...last.matchAll(/"((?:[^"\\]|\\.)*)":"((?:[^"\\]|\\.)*)"/g)].map((m) => [
  JSON.parse('"' + m[1] + '"'),
  JSON.parse('"' + m[2] + '"'),
]); // from line 1333
const names = [
  'T',
  'NAV',
  'ROUTES',
  'SERVERS',
  'FINDINGS',
  'MODES',
  'STEPS',
  'LOGT',
  'APPS',
  'ACTIONS',
  'INC',
  'USERS',
  'AUDIT',
  'D_EN',
  'TPL_TH',
  'FRAG',
  'FW_POL',
  'FW_LOCAL',
  'NET',
  'PT',
  'ENVL',
  'INIT_KEYS',
  'INIT_AGENTS',
  'INIT_APR',
  'PLUGINS',
  'PL_INST',
  'INSTALLED',
  'RT',
  'DBS',
  'TOOLS',
  'AI_STAGES',
  'AI_ACTOR',
];
const fn = new Function(
  body.replace(/<\/script>[\s\S]*$/, '') + '\nreturn {' + names.join(',') + ', trDeep};',
);
const r = fn();
const out = {};
for (const n of names) out[n] = r[n];
out.TH_D2 = Object.fromEntries(pairs);
out.EN_TPL = r.TPL_TH.map((s) => r.D_EN[s] ?? r.trDeep(s));
for (const n of [
  'SERVERS',
  'FINDINGS',
  'MODES',
  'APPS',
  'ACTIONS',
  'INC',
  'USERS',
  'AUDIT',
  'FW_POL',
  'FW_LOCAL',
  'INIT_KEYS',
  'INIT_AGENTS',
  'INIT_APR',
  'INSTALLED',
  'RT',
  'DBS',
  'LOGT',
])
  out['EN_' + n] = r.trDeep(r[n]);
fs.writeFileSync('dump.json', JSON.stringify(out, null, 1));
console.log(
  Object.keys(out)
    .map(
      (k) => k + ':' + (Array.isArray(out[k]) ? out[k].length : Object.keys(out[k] || {}).length),
    )
    .join(' '),
);
