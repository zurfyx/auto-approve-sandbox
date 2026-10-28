/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Approves low-risk pull requests from code owners as github-actions[bot].
//
// Runs from .github/workflows/auto-approve.yml on the default branch only; it
// never checks out or executes pull request code. Every gate fails closed: if
// anything cannot be read or verified, the PR is left for a human.
//
// A PR is approved only when ALL of these hold:
//   1. It is open, not a draft, targets the default branch, and does not carry
//      the `no-auto-approve` label.
//   2. Its author and the author of every commit are listed in CODEOWNERS (read
//      from the default branch, never from the PR).
//   3. No reviewer's latest review requests changes, and no human has already
//      approved it.
//   4. Every changed file (old and new path) is in the low-risk allowlist
//      (docs, tests, playground, examples) and none is in the denylist, within
//      the size caps.
//   5. The required checks are green on the exact head commit, nothing has
//      failed or is still running, and, unless the PR only touches docs, the
//      extended e2e matrix ran and passed on that commit.
//
// Modes (repo variable AUTO_APPROVE_MODE): `off`, `shadow` (default: log the
// decision to the job summary, change nothing), `on` (approve).
//
// `node .github/scripts/auto-approve.mjs --selftest` checks the classifier.

import {appendFileSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const BOT_LOGIN = 'github-actions[bot]';
const OPT_OUT_LABEL = 'no-auto-approve';
const MAX_FILES = 20;
const MAX_CHANGED_LINES = 400;
const MAX_COMMITS = 50;

const REQUIRED_CHECKS = (
  process.env.AUTO_APPROVE_REQUIRED_CHECKS ||
  [
    'core-tests / browser / browser-test',
    'core-tests / integrity (24.x)',
    'core-tests / unit (22.x)',
    'core-tests / unit (24.x)',
  ].join(',')
)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
// Extended e2e jobs are named `e2e-tests / <matrix> / e2e-test`; the canary in
// the core workflow is excluded so it cannot stand in for the full matrix.
const EXTENDED_CHECK_RE = new RegExp(
  process.env.AUTO_APPROVE_EXTENDED_CHECK_RE ||
    '^e2e-tests / (?!canary\\b).+ / e2e-test$',
);
const EXTENDED_MIN_CHECKS = Number(
  process.env.AUTO_APPROVE_EXTENDED_MIN_CHECKS || 10,
);
const OWN_CHECK_NAME = process.env.AUTO_APPROVE_OWN_CHECK || 'auto-approve';
const BAD_CONCLUSIONS = new Set([
  'failure',
  'cancelled',
  'timed_out',
  'action_required',
  'startup_failure',
  'stale',
]);

// Denylist wins over the allowlist. Anything that runs at build/install time,
// ships to npm or www, defines the public API, or changes CI stays human.
const DENY = [
  '.github/**',
  '.changeset/**',
  '.husky/**',
  '.vscode/**',
  '.claude/**',
  'AGENTS.md',
  'CLAUDE.md',
  'scripts/**',
  '**/package.json',
  '**/pnpm-lock.yaml',
  '**/package-lock.json',
  '**/yarn.lock',
  'pnpm-workspace.yaml',
  '**/.npmrc',
  '**/.nvmrc',
  '**/flow/**',
  '**/*.flow',
  'flow-typed/**',
  'libdefs/**',
  'stubs/**',
  '**/*.config.{js,cjs,mjs,ts,cts,mts}',
  '**/vite.config*',
  '**/vitest.config*',
  '**/vitest.setup*',
  '**/playwright.config*',
  '**/tsconfig*.json',
  '**/.babelrc*',
  '**/babel.config*',
  '**/eslint.config*',
  'packages/lexical-playground/index.html',
  'packages/lexical-playground/split/**',
  'packages/lexical-playground/public/**',
  'packages/lexical-playground/viteCopy*',
  'packages/lexical-playground/esm/**',
];

// Each category lists what it may touch. `needsExtended` means the extended
// e2e matrix must have passed on the head commit.
const ALLOW = [
  {
    category: 'docs',
    globs: [
      'packages/lexical-website/docs/**/*.{md,mdx}',
      'packages/*/README.md',
      'README.md',
      'examples/*/README.md',
      'dev-examples/*/README.md',
    ],
    needsExtended: false,
  },
  {
    category: 'tests',
    globs: ['packages/*/__tests__/**'],
    needsExtended: true,
  },
  {
    category: 'playground',
    globs: ['packages/lexical-playground/src/**'],
    needsExtended: true,
  },
  {
    category: 'examples',
    globs: ['examples/**', 'dev-examples/**'],
    needsExtended: true,
  },
];

function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**/` matches zero or more directories; a trailing `**` matches all.
        if (glob[i + 2] === '/') {
          re += '(?:[^/]+/)*';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const end = glob.indexOf('}', i);
      const alts = glob.slice(i + 1, end).split(',');
      re +=
        '(?:' +
        alts.map(a => a.replace(/[.+^$()|[\]\\]/g, '\\$&')).join('|') +
        ')';
      i = end;
    } else {
      re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp('^' + re + '$');
}

const DENY_RES = DENY.map(globToRegExp);
const ALLOW_RES = ALLOW.map(a => ({...a, res: a.globs.map(globToRegExp)}));

// Returns {ok, category?, needsExtended?, reason?} for one path.
export function classifyPath(path) {
  // Only plain ASCII paths without traversal or control/bidi characters.
  if (!/^[A-Za-z0-9._\-/@+ ]+$/.test(path) || path.split('/').includes('..')) {
    return {ok: false, reason: `unusual path ${JSON.stringify(path)}`};
  }
  if (DENY_RES.some(re => re.test(path))) {
    return {ok: false, reason: `denylisted path ${path}`};
  }
  for (const a of ALLOW_RES) {
    if (a.res.some(re => re.test(path))) {
      return {category: a.category, needsExtended: a.needsExtended, ok: true};
    }
  }
  return {ok: false, reason: `path outside the low-risk allowlist: ${path}`};
}

// files: [{filename, previous_filename?, status, additions, deletions}]
export function classifyFiles(files) {
  const categories = new Set();
  let needsExtended = false;
  let lines = 0;
  if (files.length === 0) {
    return {ok: false, reason: 'no changed files'};
  }
  if (files.length > MAX_FILES) {
    return {ok: false, reason: `${files.length} files > ${MAX_FILES}`};
  }
  for (const f of files) {
    for (const p of [f.filename, f.previous_filename].filter(Boolean)) {
      const c = classifyPath(p);
      if (!c.ok) {
        return c;
      }
      categories.add(c.category);
      needsExtended ||= c.needsExtended;
      if (c.category === 'tests' && f.status === 'removed') {
        return {ok: false, reason: `removes a test file: ${p}`};
      }
    }
    lines += (f.additions || 0) + (f.deletions || 0);
  }
  if (lines > MAX_CHANGED_LINES) {
    return {ok: false, reason: `${lines} changed lines > ${MAX_CHANGED_LINES}`};
  }
  return {categories: [...categories].sort(), lines, needsExtended, ok: true};
}

export function parseCodeowners(text) {
  const owners = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) {
      continue;
    }
    for (const tok of line.split(/\s+/).slice(1)) {
      // Individual users only; teams (@org/team) and emails are ignored.
      if (/^@[A-Za-z0-9-]+$/.test(tok)) {
        owners.add(tok.slice(1).toLowerCase());
      }
    }
  }
  return owners;
}

// ---------------------------------------------------------------------------

const API = process.env.GITHUB_API_URL || 'https://api.github.com';

async function gh(path, {method = 'GET', body} = {}) {
  const res = await fetch(path.startsWith('http') ? path : `${API}${path}`, {
    body: body ? JSON.stringify(body) : undefined,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${process.env.GH_TOKEN}`,
      'X-GitHub-Api-Version': '2022-11-28',
    },
    method,
  });
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status} ${await res.text()}`);
  }
  return {data: res.status === 204 ? null : await res.json(), res};
}

async function ghAll(path, pick = d => d) {
  const out = [];
  let url = `${API}${path}${path.includes('?') ? '&' : '?'}per_page=100`;
  for (let page = 0; url && page < 30; page++) {
    const {data, res} = await gh(url);
    out.push(...pick(data));
    const next = (res.headers.get('link') || '').match(
      /<([^>]+)>;\s*rel="next"/,
    );
    url = next ? next[1] : null;
  }
  if (url) {
    throw new Error(`too many pages for ${path}`);
  }
  return out;
}

class Skip extends Error {}
const skip = msg => {
  throw new Skip(msg);
};

function summary(lines) {
  const text = lines.join('\n') + '\n';
  process.stdout.write(text);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, text);
  }
}

async function findPr(repo) {
  if (process.env.PR_NUMBER) {
    return (await gh(`/repos/${repo}/pulls/${Number(process.env.PR_NUMBER)}`))
      .data;
  }
  const sha = process.env.HEAD_SHA;
  if (!/^[0-9a-f]{40}$/.test(sha || '')) {
    skip('no head sha in the triggering event');
  }
  // workflow_run.pull_requests is empty for fork PRs, so match on head sha.
  const open = await ghAll(`/repos/${repo}/pulls?state=open`);
  const matches = open.filter(p => p.head.sha === sha);
  if (matches.length !== 1) {
    skip(`${matches.length} open PRs have head ${sha}`);
  }
  // The list endpoint omits commits/changed_files; read the full PR.
  return (await gh(`/repos/${repo}/pulls/${matches[0].number}`)).data;
}

async function evaluate(repo, pr, owners, defaultBranch) {
  const facts = [];
  const headSha = pr.head.sha;

  // 1. PR state.
  if (pr.state !== 'open' || pr.draft) {
    skip('not open or still a draft');
  }
  if (pr.base.ref !== defaultBranch || pr.base.repo.full_name !== repo) {
    skip(`base is ${pr.base.repo.full_name}:${pr.base.ref}`);
  }
  if (pr.labels.some(l => l.name === OPT_OUT_LABEL)) {
    skip(`labelled ${OPT_OUT_LABEL}`);
  }

  // 2. Code owners only.
  const author = pr.user.login.toLowerCase();
  if (!owners.has(author)) {
    skip(`author ${pr.user.login} is not in CODEOWNERS`);
  }
  if (pr.commits > MAX_COMMITS) {
    skip(`${pr.commits} commits > ${MAX_COMMITS}`);
  }
  const commits = await ghAll(`/repos/${repo}/pulls/${pr.number}/commits`);
  if (commits.length !== pr.commits) {
    skip('could not list every commit');
  }
  for (const c of commits) {
    const a = c.author && c.author.login ? c.author.login.toLowerCase() : null;
    const k =
      c.committer && c.committer.login ? c.committer.login.toLowerCase() : null;
    if (!a || !owners.has(a)) {
      skip(
        `commit ${c.sha.slice(0, 10)} author ${a ?? '(unlinked)'} is not a code owner`,
      );
    }
    if (!k || !(owners.has(k) || k === 'web-flow')) {
      skip(
        `commit ${c.sha.slice(0, 10)} committer ${k ?? '(unlinked)'} is not a code owner`,
      );
    }
  }
  facts.push(`author and all ${commits.length} commit(s) by code owners`);

  // 3. Reviews.
  const reviews = await ghAll(`/repos/${repo}/pulls/${pr.number}/reviews`);
  const latest = new Map();
  for (const r of reviews) {
    if (r.state !== 'COMMENTED' && r.user) {
      latest.set(r.user.login, r);
    }
  }
  for (const [login, r] of latest) {
    if (r.state === 'CHANGES_REQUESTED') {
      skip(`${login} requested changes`);
    }
    if (r.state === 'APPROVED' && login !== BOT_LOGIN) {
      skip(`already approved by ${login}`);
    }
    if (
      r.state === 'APPROVED' &&
      login === BOT_LOGIN &&
      r.commit_id === headSha
    ) {
      skip('already auto-approved at this head');
    }
  }

  // 4. Files.
  const files = await ghAll(`/repos/${repo}/pulls/${pr.number}/files`);
  if (files.length !== pr.changed_files) {
    skip(`listed ${files.length} of ${pr.changed_files} files`);
  }
  const cls = classifyFiles(files);
  if (!cls.ok) {
    skip(cls.reason);
  }
  facts.push(
    `${files.length} file(s), ${cls.lines} line(s), all low risk (${cls.categories.join(', ')})`,
  );

  // 5. CI on the exact head commit.
  const runs = await ghAll(
    `/repos/${repo}/commits/${headSha}/check-runs?filter=latest`,
    d => d.check_runs,
  );
  const others = runs.filter(r => r.name !== OWN_CHECK_NAME);
  const bad = others.filter(r => BAD_CONCLUSIONS.has(r.conclusion));
  if (bad.length) {
    skip(
      `check failed: ${bad.map(r => `${r.name}=${r.conclusion}`).join(', ')}`,
    );
  }
  const pending = others.filter(r => r.status !== 'completed');
  if (pending.length) {
    skip(`checks still running: ${pending.map(r => r.name).join(', ')}`);
  }
  for (const name of REQUIRED_CHECKS) {
    const r = others.find(x => x.name === name);
    if (!r || r.conclusion !== 'success') {
      skip(`required check ${name} is ${r ? r.conclusion : 'missing'}`);
    }
  }
  if (cls.needsExtended) {
    const e2e = others.filter(r => EXTENDED_CHECK_RE.test(r.name));
    const ok = e2e.filter(r => r.conclusion === 'success');
    if (ok.length < EXTENDED_MIN_CHECKS || ok.length !== e2e.length) {
      skip(
        `extended e2e: ${ok.length}/${e2e.length} passed (need >= ${EXTENDED_MIN_CHECKS}); add the extended-tests label`,
      );
    }
    facts.push(`required checks and ${ok.length} extended e2e jobs green`);
  } else {
    facts.push('required checks green');
  }
  const status = (await gh(`/repos/${repo}/commits/${headSha}/status`)).data;
  const badStatus = status.statuses.filter(s =>
    ['failure', 'error'].includes(s.state),
  );
  if (badStatus.length) {
    skip(`status failed: ${badStatus.map(s => s.context).join(', ')}`);
  }
  return facts;
}

async function main() {
  const repo = process.env.REPO;
  const mode = (process.env.MODE || 'shadow').toLowerCase();
  if (mode === 'off') {
    summary(['Auto-approve is off (AUTO_APPROVE_MODE=off).']);
    return;
  }
  const repoInfo = (await gh(`/repos/${repo}`)).data;
  const owners = parseCodeowners(readFileSync('.github/CODEOWNERS', 'utf8'));
  if (owners.size === 0) {
    throw new Error('no individual owners in CODEOWNERS');
  }
  let pr;
  try {
    pr = await findPr(repo);
  } catch (e) {
    if (e instanceof Skip) {
      summary([`Auto-approve: nothing to do (${e.message}).`]);
      return;
    }
    throw e;
  }
  const headSha = pr.head.sha;
  const title = `Auto-approve #${pr.number} @ ${headSha.slice(0, 10)} (mode: ${mode})`;
  let facts;
  try {
    facts = await evaluate(repo, pr, owners, repoInfo.default_branch);
  } catch (e) {
    if (e instanceof Skip) {
      summary([`### ${title}`, '', `Not approved: ${e.message}.`]);
      return;
    }
    throw e;
  }
  const body = [
    'Automated low-risk check, not a maintainer review.',
    '',
    ...facts.map(f => `- ${f}`),
    `- evaluated at ${headSha}`,
    '',
    `Rules: \`.github/scripts/auto-approve.mjs\`. Add the \`${OPT_OUT_LABEL}\` label to opt out, or dismiss this review to revoke it.`,
  ].join('\n');
  if (mode !== 'on') {
    summary([`### ${title}`, '', 'Would approve (shadow mode):', '', body]);
    return;
  }
  const review = (
    await gh(`/repos/${repo}/pulls/${pr.number}/reviews`, {
      body: {body, commit_id: headSha, event: 'APPROVE'},
      method: 'POST',
    })
  ).data;
  // If the head moved while we were evaluating, take the approval back.
  const fresh = (await gh(`/repos/${repo}/pulls/${pr.number}`)).data;
  if (fresh.head.sha !== headSha) {
    await gh(
      `/repos/${repo}/pulls/${pr.number}/reviews/${review.id}/dismissals`,
      {
        body: {
          message: `Head moved to ${fresh.head.sha} during evaluation; re-evaluating.`,
        },
        method: 'PUT',
      },
    );
    summary([
      `### ${title}`,
      '',
      `Approved then dismissed: head moved to ${fresh.head.sha}.`,
    ]);
    return;
  }
  summary([`### ${title}`, '', 'Approved:', '', body]);
}

function selftest() {
  const cases = [
    ['packages/lexical-website/docs/concepts/editor-state.md', true],
    ['packages/lexical-website/docs/intro.mdx', true],
    ['packages/lexical-table/README.md', true],
    ['README.md', true],
    ['packages/lexical/__tests__/unit/LexicalEditor.test.ts', true],
    ['packages/lexical-playground/__tests__/e2e/Tables.spec.mjs', true],
    ['packages/lexical-playground/src/plugins/ToolbarPlugin/index.tsx', true],
    ['examples/markdown-editor/src/App.tsx', true],
    ['examples/markdown-editor/package.json', false],
    ['packages/lexical-playground/package.json', false],
    ['packages/lexical-playground/vite.config.ts', false],
    ['packages/lexical-playground/index.html', false],
    ['packages/lexical/src/LexicalEditor.ts', false],
    ['packages/lexical/src/index.ts', false],
    ['packages/lexical/flow/Lexical.js.flow', false],
    ['packages/lexical-link/src/index.ts', false],
    ['packages/lexical-website/docusaurus.config.ts', false],
    ['packages/lexical-website/plugins/package-docs/index.mjs', false],
    ['packages/lexical-website/src/components/Foo.tsx', false],
    ['.github/workflows/tests.yml', false],
    ['.github/CODEOWNERS', false],
    ['scripts/build.mjs', false],
    ['pnpm-lock.yaml', false],
    ['.changeset/brave-cats.md', false],
    ['AGENTS.md', false],
    ['vitest.config.mts', false],
    ['playwright.config.mjs', false],
    ['packages/lexical-website/docs/../../../.github/x.md', false],
    ['packages/lexical-website/docs/\u202eevil.md', false],
  ];
  let failed = 0;
  for (const [p, want] of cases) {
    const got = classifyPath(p).ok;
    if (got !== want) {
      failed++;
      console.error(`FAIL ${p}: got ${got}, want ${want}`);
    }
  }
  const rename = classifyFiles([
    {
      additions: 0,
      deletions: 0,
      filename: 'packages/lexical-website/docs/x.md',
      previous_filename: '.github/workflows/x.yml',
      status: 'renamed',
    },
  ]);
  if (rename.ok) {
    failed++;
    console.error('FAIL rename out of .github accepted');
  }
  const removedTest = classifyFiles([
    {
      additions: 0,
      deletions: 40,
      filename: 'packages/lexical/__tests__/unit/A.test.ts',
      status: 'removed',
    },
  ]);
  if (removedTest.ok) {
    failed++;
    console.error('FAIL removed test accepted');
  }
  const docsOnly = classifyFiles([
    {
      additions: 3,
      deletions: 1,
      filename: 'packages/lexical-website/docs/a.md',
      status: 'modified',
    },
  ]);
  if (!docsOnly.ok || docsOnly.needsExtended) {
    failed++;
    console.error('FAIL docs-only should pass without extended');
  }
  const big = classifyFiles([
    {
      additions: 401,
      deletions: 0,
      filename: 'packages/lexical-website/docs/a.md',
      status: 'modified',
    },
  ]);
  if (big.ok) {
    failed++;
    console.error('FAIL size cap');
  }
  const owners = parseCodeowners(
    '# comment\n* @Zurfyx @etrepum @meta/team me@x.com\n',
  );
  if (!owners.has('zurfyx') || !owners.has('etrepum') || owners.size !== 2) {
    failed++;
    console.error('FAIL codeowners parse', [...owners]);
  }
  process.stdout.write(
    failed ? `${failed} selftest failure(s)\n` : 'selftest ok\n',
  );
  process.exit(failed ? 1 : 0);
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (!isMain) {
  // Imported (e.g. by a backtest): expose the classifier only.
} else if (process.argv.includes('--selftest')) {
  selftest();
} else {
  main().catch(e => {
    console.error(e);
    summary([`Auto-approve errored (nothing approved): ${e.message}`]);
    process.exit(1);
  });
}
