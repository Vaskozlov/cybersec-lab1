import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTestResults, testsPassed } from '../scripts/ci-summary.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const summaryScript = join(root, 'scripts/ci-summary.js');
const reportScript = join(root, 'scripts/build_report.py');
function temporaryDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), 'lab1-ci-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function childEnvironment(extra = {}) {
  const environment = { ...process.env, ...extra };
  // A child test runner must be a fresh run, not an IPC child of this node:test process.
  delete environment.NODE_TEST_CONTEXT;
  return environment;
}
function testLog({ total = 2, passed = 2, failed = 0, cancelled = 0, skipped = 0, todo = 0 } = {}) {
  return `ℹ tests ${total}\nℹ suites 0\nℹ pass ${passed}\nℹ fail ${failed}\nℹ cancelled ${cancelled}\nℹ skipped ${skipped}\nℹ todo ${todo}\n`;
}
function runSummary(t, log, outcomes = {}) {
  const directory = temporaryDirectory(t);
  mkdirSync(join(directory, 'reports'));
  if (log !== null) writeFileSync(join(directory, 'reports/tests.txt'), log);
  writeFileSync(join(directory, 'reports/eslint.json'), JSON.stringify([{ errorCount: 0, warningCount: 0 }]));
  const destination = join(directory, 'summary.md');
  const result = spawnSync(process.execPath, [summaryScript, 'sast'], {
    cwd: directory, encoding: 'utf8',
    env: childEnvironment({ GITHUB_STEP_SUMMARY: destination, TEST_OUTCOME: 'success', SAST_OUTCOME: 'success', ...outcomes }),
  });
  return { ...result, summary: readFileSync(destination, 'utf8') };
}
function python(code, args = []) {
  return spawnSync('python3', ['-B', '-c',
    'import importlib.util, sys\nfrom pathlib import Path\n'
    + 'spec = importlib.util.spec_from_file_location("build_report", sys.argv[1])\n'
    + 'module = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n' + code,
    reportScript, ...args], { encoding: 'utf8', env: childEnvironment() });
}

test('CI pipefail rejects an actual failing test before tee and stops the next stage', (t) => {
  const workflow = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
  assert.match(workflow, /^defaults:\n  run:\n    shell: bash$/m);
  const match = workflow.match(/      - name: Test API and attack scenarios\n        id: tests\n        run: \|\n((?:          .+\n)+)/);
  assert.ok(match, 'Use the actual test step from the workflow');
  const command = match[1].replaceAll(/^          /gm, '') + 'printf reached > next-stage\n';
  const directory = temporaryDirectory(t);
  mkdirSync(join(directory, 'bin'));
  writeFileSync(join(directory, 'failing.test.mjs'),
    "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('intentional negative fixture', () => assert.fail('intentional failure'));\n");
  writeFileSync(join(directory, 'bin/npm'),
    '#!/bin/sh\nexec "$NODE_FOR_CI_TEST" --test --test-reporter=spec failing.test.mjs\n', { mode: 0o700 });
  const options = { cwd: directory, encoding: 'utf8', env: childEnvironment({
    NODE_FOR_CI_TEST: process.execPath, PATH: `${join(directory, 'bin')}:${process.env.PATH}`,
  }) };
  const failing = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', command], options);
  assert.equal(failing.status, 1, failing.stderr);
  assert.equal(existsSync(join(directory, 'next-stage')), false);
  const counts = parseTestResults(readFileSync(join(directory, 'reports/tests.txt'), 'utf8'));
  assert.equal(counts.total, 1);
  assert.equal(counts.failed, 1);
  // This control reproduces the former false-green behavior and makes the regression meaningful.
  const unsafe = spawnSync('bash', ['--noprofile', '--norc', '-e', '-c', command], options);
  assert.equal(unsafe.status, 0, unsafe.stderr);
  assert.equal(existsSync(join(directory, 'next-stage')), true);
});

test('summary independently verifies and displays a complete passing test run', (t) => {
  const result = runSummary(t, `\u001b[32m${testLog()}\u001b[0m`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.summary, /Test results: PASS/);
  assert.match(result.summary, /\| 2 \| 2 \| 0 \| 0 \| 0 \| 0 \|/);
  assert.match(result.summary, /Security check status: PASS/);
  const parsed = python('print(module.parse_test_results(sys.argv[2]))\n', [testLog()]);
  assert.equal(parsed.status, 0, parsed.stderr);
  assert.match(parsed.stdout, /'tests_total': 2/);
});

test('summary and independent Python parser reject failed, empty, skipped and incomplete test runs', (t) => {
  const logs = [
    testLog({ passed: 1, failed: 1 }), testLog({ total: 0, passed: 0 }),
    testLog({ passed: 1, skipped: 1 }), testLog({ passed: 1, cancelled: 1 }),
    testLog({ passed: 1, todo: 1 }), testLog().replace('ℹ fail 0\n', ''),
    testLog() + 'ℹ tests 2\n', 'runner terminated before producing its summary\n',
  ];
  for (const log of logs) {
    const result = runSummary(t, log);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.summary, /Test results: FAIL/);
    assert.match(result.summary, /Security check status: FAIL/);
    const independent = python('module.parse_test_results(sys.argv[2])\n', [log]);
    assert.notEqual(independent.status, 0, independent.stdout);
    let passed = false;
    try { passed = testsPassed(parseTestResults(log)); } catch { /* An incomplete summary must fail. */ }
    assert.equal(passed, false);
  }
  const missing = runSummary(t, null);
  assert.equal(missing.status, 1, missing.stderr);
  assert.match(missing.summary, /Test log was not produced/);
});

test('always-run summary preserves failed command outcomes even when saved counters look clean', (t) => {
  for (const outcomes of [{ TEST_OUTCOME: 'failure' }, { SAST_OUTCOME: 'skipped' }]) {
    const result = runSummary(t, testLog(), outcomes);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.summary, /Security check status: FAIL/);
    assert.match(result.summary, /did not succeed/);
  }
});

test('report gate checks raw test and audit evidence instead of trusting a success summary', (t) => {
  const directory = temporaryDirectory(t);
  for (const name of ['ci-result.json', 'ci-run.json', 'ci-jobs.json', 'tests.txt', 'npm-audit.json',
    'dependency-check-report.json', 'eslint.json', 'actions-sast.log', 'actions-sca.log']) {
    cpSync(join(root, 'output/evidence', name), join(directory, name));
  }
  const ci = JSON.parse(readFileSync(join(directory, 'ci-result.json'), 'utf8'));
  const log = readFileSync(join(directory, 'tests.txt'), 'utf8');
  const counts = parseTestResults(log);
  Object.assign(ci, { tests_total: counts.total, tests_passed: counts.passed, tests_failed: counts.failed,
    tests_cancelled: counts.cancelled, tests_skipped: counts.skipped, tests_todo: counts.todo });
  writeFileSync(join(directory, 'ci-result.json'), JSON.stringify(ci));
  const validate = () => python('module.validate_evidence(Path(sys.argv[2]), Path(sys.argv[3]))\n', [directory, resolve(root)]);
  const clean = validate();
  assert.equal(clean.status, 0, clean.stderr);
  writeFileSync(join(directory, 'tests.txt'), testLog({ total: counts.total, passed: counts.total - 1, failed: 1 }));
  const failedTests = validate();
  assert.notEqual(failedTests.status, 0);
  assert.match(failedTests.stderr, /Tests did not all pass/);
  writeFileSync(join(directory, 'tests.txt'), log);
  const audit = JSON.parse(readFileSync(join(directory, 'npm-audit.json'), 'utf8'));
  audit.metadata.vulnerabilities.total = 1;
  writeFileSync(join(directory, 'npm-audit.json'), JSON.stringify(audit));
  const failedAudit = validate();
  assert.notEqual(failedAudit.status, 0);
  assert.match(failedAudit.stderr, /npm audit totals/);
});
