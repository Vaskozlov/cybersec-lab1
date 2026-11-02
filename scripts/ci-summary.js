import { readFileSync, appendFileSync, existsSync } from 'node:fs';
import { stripVTControlCharacters } from 'node:util';

export function parseTestResults(log) {
  const values = new Map();
  const clean = stripVTControlCharacters(log).replaceAll('\r\n', '\n');
  for (const match of clean.matchAll(/^(?:ℹ )?(tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)) {
    if (values.has(match[1])) throw new Error(`Duplicate test counter: ${match[1]}`);
    const value = Number(match[2]);
    if (!Number.isSafeInteger(value)) throw new Error('Invalid test counter');
    values.set(match[1], value);
  }
  if (values.size !== 6) throw new Error('Test runner summary is missing or incomplete');
  return {
    total: values.get('tests'), passed: values.get('pass'), failed: values.get('fail'),
    cancelled: values.get('cancelled'), skipped: values.get('skipped'), todo: values.get('todo'),
  };
}

export function testsPassed(counts) {
  return counts.total > 0 && counts.passed === counts.total && counts.failed === 0
    && counts.cancelled === 0 && counts.skipped === 0 && counts.todo === 0;
}

function main() {
  const destination = process.env.GITHUB_STEP_SUMMARY;
  if (!destination) throw new Error('GITHUB_STEP_SUMMARY is required');
  const mode = process.argv[2];
  const issues = [];
  let summary = '';
  const outcome = (label, value) => {
    summary += `${label}: **${value || 'missing'}**.\n\n`;
    if (value !== 'success') issues.push(`${label} did not succeed`);
  };
  if (mode === 'sast') {
    summary += '## API tests and SAST\n\n';
    outcome('Test command', process.env.TEST_OUTCOME);
    if (existsSync('reports/tests.txt')) {
      const log = stripVTControlCharacters(readFileSync('reports/tests.txt', 'utf8'));
      try {
        const counts = parseTestResults(log);
        const passed = testsPassed(counts);
        summary += `### Test results: ${passed ? 'PASS' : 'FAIL'}\n\n`;
        summary += '| Total | Passed | Failed | Cancelled | Skipped | Todo |\n| --- | --- | --- | --- | --- | --- |\n';
        summary += `| ${counts.total} | ${counts.passed} | ${counts.failed} | ${counts.cancelled} | ${counts.skipped} | ${counts.todo} |\n\n`;
        if (!passed) issues.push('The test log does not confirm a complete passing run');
      } catch (error) {
        issues.push(error.message);
        summary += `### Test results: FAIL\n\n${error.message}.\n\n`;
      }
      summary += `### Test runner output\n\n\`\`\`text\n${log}\n\`\`\`\n\n`;
    } else issues.push('Test log was not produced');
    outcome('SAST command', process.env.SAST_OUTCOME);
    if (existsSync('reports/eslint.json')) {
      try {
        const files = JSON.parse(readFileSync('reports/eslint.json', 'utf8'));
        const errors = files.reduce((sum, file) => sum + file.errorCount, 0);
        const warnings = files.reduce((sum, file) => sum + file.warningCount, 0);
        summary += `### ESLint + eslint-plugin-security\n\nFiles scanned: **${files.length}**. Errors: **${errors}**. Warnings: **${warnings}**.\n\n`;
        if (!files.length || errors !== 0 || warnings !== 0) issues.push('SAST did not produce a clean scan');
      } catch { issues.push('SAST JSON report is invalid'); }
    } else issues.push('SAST JSON report was not produced');
  } else if (mode === 'sca') {
    summary += '## Software composition analysis\n\n';
    outcome('npm audit command', process.env.AUDIT_OUTCOME);
    if (existsSync('reports/npm-audit.json')) {
      try {
        const audit = JSON.parse(readFileSync('reports/npm-audit.json', 'utf8'));
        summary += `### npm audit (all dependencies)\n\n\`\`\`json\n${JSON.stringify(audit.metadata, null, 2)}\n\`\`\`\n\n`;
        if (audit.error || !audit.metadata?.vulnerabilities
          || audit.metadata.vulnerabilities.high !== 0 || audit.metadata.vulnerabilities.critical !== 0) {
          issues.push('npm audit did not confirm a clean high/critical vulnerability check');
        }
      } catch { issues.push('npm audit JSON report is invalid'); }
    } else issues.push('npm audit report was not produced');
    outcome('Dependency-Check command', process.env.ODC_OUTCOME);
    if (existsSync('reports/dependency-check-report.json')) {
      try {
        const report = JSON.parse(readFileSync('reports/dependency-check-report.json', 'utf8'));
        const dependencies = report.dependencies ?? [];
        const vulnerable = dependencies.filter((entry) => (entry.vulnerabilities ?? []).length > 0);
        summary += `### OWASP Dependency-Check ${report.scanInfo?.engineVersion ?? ''}\n\n`;
        summary += `Dependencies analyzed: **${dependencies.length}**. Dependencies with reported vulnerabilities: **${vulnerable.length}**.\n\n`;
        summary += 'Policy: fail at CVSS >= 7; scanner and download errors also fail the job.\n\n';
        if (!dependencies.length || report.scanInfo?.analysisExceptions?.length) {
          issues.push('Dependency-Check did not complete a valid dependency analysis');
        }
      } catch { issues.push('Dependency-Check JSON report is invalid'); }
    } else issues.push('Dependency-Check report was not produced');
  } else throw new Error('Expected summary mode: sast or sca');
  summary += `### Security check status: ${issues.length ? 'FAIL' : 'PASS'}\n\n`;
  if (issues.length) summary += issues.map((issue) => `- ${issue}.\n`).join('');
  // GitHub runner supplies this local output path; no HTTP input can control it.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  appendFileSync(destination, summary);
  if (issues.length) process.exitCode = 1;
}

if (import.meta.main) main();
