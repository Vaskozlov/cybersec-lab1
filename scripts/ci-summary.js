import { readFileSync, appendFileSync, existsSync } from 'node:fs';

const destination = process.env.GITHUB_STEP_SUMMARY;
if (!destination) throw new Error('GITHUB_STEP_SUMMARY is required');
const mode = process.argv[2];
let summary = '';
if (mode === 'sast') {
  summary += '## API tests and SAST\n\n';
  if (existsSync('reports/tests.txt')) {
    // Strip terminal escape sequences before placing the real test log in Markdown.
    const log = readFileSync('reports/tests.txt', 'utf8').replaceAll('\u001b', '');
    summary += `### Test runner output\n\n\`\`\`text\n${log}\n\`\`\`\n\n`;
  }
  if (existsSync('reports/eslint.json')) {
    const files = JSON.parse(readFileSync('reports/eslint.json', 'utf8'));
    const errors = files.reduce((sum, file) => sum + file.errorCount, 0);
    const warnings = files.reduce((sum, file) => sum + file.warningCount, 0);
    summary += `### ESLint + eslint-plugin-security\n\nFiles scanned: **${files.length}**. Errors: **${errors}**. Warnings: **${warnings}**.\n`;
  } else summary += 'SAST JSON report was not produced. Check the job logs.\n';
} else if (mode === 'sca') {
  summary += '## Software composition analysis\n\n';
  if (existsSync('reports/npm-audit.json')) {
    const audit = JSON.parse(readFileSync('reports/npm-audit.json', 'utf8'));
    summary += `### npm audit (all dependencies)\n\n\`\`\`json\n${JSON.stringify(audit.metadata, null, 2)}\n\`\`\`\n\n`;
  }
  if (existsSync('reports/dependency-check-report.json')) {
    const report = JSON.parse(readFileSync('reports/dependency-check-report.json', 'utf8'));
    const dependencies = report.dependencies ?? [];
    const vulnerable = dependencies.filter((entry) => (entry.vulnerabilities ?? []).length > 0);
    summary += `### OWASP Dependency-Check ${report.scanInfo?.engineVersion ?? ''}\n\n`;
    summary += `Dependencies analyzed: **${dependencies.length}**. Dependencies with reported vulnerabilities: **${vulnerable.length}**.\n\n`;
    summary += 'Policy: fail at CVSS >= 7; scanner and download errors also fail the job.\n';
  } else summary += 'Dependency-Check report was not produced. Check the job logs.\n';
}
// GitHub runner supplies this local output path; no HTTP input can control it.
// eslint-disable-next-line security/detect-non-literal-fs-filename
appendFileSync(destination, summary);
