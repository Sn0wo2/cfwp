'use strict';

// Compare the CI jobs shared with the rust-template checkout (../template,
// override with TEMPLATE_DIR) so drift shows up instead of accumulating.
// The build/release/deploy jobs, geiger toolchain, and rust-toolchain setup
// diverge by design and are masked out here.

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const templateRoot = path.resolve(
  process.env.TEMPLATE_DIR || path.join(repoRoot, '..', 'template'),
);
const cfwpCi = path.join(repoRoot, '.github', 'workflows', 'ci.yml');
const templateCi = path.join(templateRoot, '.github', 'workflows', 'ci.yml');

// Step blocks that legitimately differ between the repos. Only the check job
// needs masks; audit is compared verbatim.
const checkSkips = [
  /actions\/setup-rust$/, // pinned nightly from rust-toolchain.toml
  /dtolnay\/rust-toolchain@/, // floating stable, template-only
  /Swatinem\/rust-cache@/, // cfwp caches inside setup-rust
  /collect-ci-metadata/, // template-only build gating inputs
];

const jobSkips = { check: checkSkips, audit: [] };

const STEP = /^      - /;
const JOB = /^  [A-Za-z][\w-]*:$/;

function readLines(file) {
  return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n').split('\n');
}

function extractJob(lines, name) {
  const start = lines.indexOf(`  ${name}:`);
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (JOB.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end);
}

// Split the steps section into blocks; each block runs from its `      - `
// line up to the next step marker, with trailing blank lines trimmed.
function stepBlocks(job) {
  const start = job.indexOf('    steps:');
  if (start === -1) return null;
  const blocks = [];
  for (let i = start + 1; i < job.length; i += 1) {
    if (!STEP.test(job[i])) continue;
    let j = i + 1;
    while (j < job.length && !STEP.test(job[j])) j += 1;
    const body = job.slice(i + 1, j);
    while (body.length && body[body.length - 1].trim() === '') body.pop();
    blocks.push([job[i], ...body]);
    i = j - 1;
  }
  return blocks;
}

// Drop job-level blocks like the template-only outputs (has_binaries /
// has_library) that gate the template's build matrix.
function dropJobLevelBlocks(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i] === '    outputs:') {
      let j = i + 1;
      while (j < lines.length && /^ {6}/.test(lines[j])) j += 1;
      i = j - 1;
      continue;
    }
    out.push(lines[i]);
  }
  return out;
}

function signature(lines, skips) {
  const job = dropJobLevelBlocks(lines);
  const blocks = stepBlocks(job);
  if (blocks === null) return null;
  const kept = [];
  let skipped = 0;
  for (const block of blocks) {
    if (skips.some((pattern) => block.some((line) => pattern.test(line)))) {
      skipped += 1;
      continue;
    }
    kept.push(block.join('\n'));
  }
  return { kept, skipped };
}

function diffSeq(a, b) {
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push(`  ${a[i]}`);
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push(`- ${a[i]}`);
      i += 1;
    } else {
      out.push(`+ ${b[j]}`);
      j += 1;
    }
  }
  while (i < n) {
    out.push(`- ${a[i]}`);
    i += 1;
  }
  while (j < m) {
    out.push(`+ ${b[j]}`);
    j += 1;
  }
  return out;
}

if (!fs.existsSync(templateCi)) {
  console.error(`template ci.yml not found at ${templateCi} (set TEMPLATE_DIR to the checkout)`);
  process.exit(1);
}

const templateLabel = path.basename(templateRoot);
let drifted = false;

for (const jobName of ['check', 'audit']) {
  const skips = jobSkips[jobName];
  const ours = signature(extractJob(readLines(cfwpCi), jobName), skips);
  const theirs = signature(extractJob(readLines(templateCi), jobName), skips);
  if (!ours || !theirs) {
    console.log(`?   ${jobName}: job missing on one side, skipped`);
    continue;
  }
  console.log(`i   ${jobName}: masked ${ours.skipped} local / ${theirs.skipped} template step(s)`);
  const diff = diffSeq(ours.kept, theirs.kept);
  const inSync = diff.every((line) => line.startsWith('  '));
  if (inSync) {
    console.log(`ok  ${jobName}: in sync with ${templateLabel}`);
  } else {
    drifted = true;
    console.log(`diff ${jobName}: cfwp <, ${templateLabel} >`);
    for (const line of diff) {
      if (!line.startsWith('  ')) console.log(`    ${line.replace(/\n/g, '\n    ')}`);
    }
  }
}

process.exit(drifted ? 1 : 0);
