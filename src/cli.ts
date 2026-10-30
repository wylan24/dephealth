#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { analyze } from './analyze.ts';
import { loadConfig } from './config.ts';
import { DiskCache } from './fetchers/http.ts';
import { evaluate, parseRules, RULE_HELP } from './report/ci.ts';
import { renderHtml } from './report/html.ts';
import { renderSarif } from './report/sarif.ts';
import { renderText } from './report/text.ts';
import type { Ecosystem } from './types.ts';

const VERSION = (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;

const HELP = `dephealth ${VERSION} — dependency health report for npm and Python projects

Usage: dephealth [project-dir] [options]

Output
  --html <file>         write the interactive HTML report (default: dephealth-report.html)
  --no-html             don't write the HTML report
  --json <file>         write the JSON report ("-" for stdout)
  --sarif <file>        write SARIF 2.1.0 for GitHub code scanning
  --top <n>             actions to list in the terminal (default 10)
  --quiet               no progress or terminal summary

Checks
  --deep                fetch registry metadata for transitive packages too (slower)
  --bundle              measure browser bundle size with esbuild (frontend workspaces)
  --prod                ignore dev dependencies (devDependencies, dev groups, dev requirements)
  --ecosystem <list>    npm, pypi or both, comma-separated (default: every one detected)
  --no-search           don't search npm for replacement candidates
  --config <file>       config file (default: .dephealthrc.json or "dephealth" in package.json)

CI
  --ci                  exit 1 when any --fail-on rule is violated
  --fail-on <rules>     comma-separated rules (default: from config, else vuln:high,deprecated:direct)

Network
  --github-token <t>    GitHub token (default: $GITHUB_TOKEN or $GH_TOKEN); optional but recommended
  --cache-dir <dir>     response cache (24h) location
  --no-cache            don't read or write the cache

${RULE_HELP}
`;

function parseEcosystems(value: string | undefined): Ecosystem[] | undefined {
  if (!value) return undefined;
  return value.split(',').map((v) => {
    const key = v.trim().toLowerCase();
    if (key === 'npm' || key === 'node' || key === 'js') return 'npm' as const;
    if (key === 'pypi' || key === 'python' || key === 'py') return 'PyPI' as const;
    throw new Error(`Unknown ecosystem "${v}" (use npm or pypi)`);
  });
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      html: { type: 'string' },
      'no-html': { type: 'boolean' },
      json: { type: 'string' },
      sarif: { type: 'string' },
      top: { type: 'string' },
      quiet: { type: 'boolean', short: 'q' },
      deep: { type: 'boolean' },
      bundle: { type: 'boolean' },
      prod: { type: 'boolean' },
      ecosystem: { type: 'string' },
      'no-search': { type: 'boolean' },
      config: { type: 'string' },
      ci: { type: 'boolean' },
      'fail-on': { type: 'string' },
      'github-token': { type: 'string' },
      'cache-dir': { type: 'string' },
      'no-cache': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (values.version) {
    process.stdout.write(VERSION + '\n');
    return 0;
  }

  const root = path.resolve(positionals[0] ?? '.');
  const { config, file: configFile } = loadConfig(root, values.config);
  const rules = parseRules(values['fail-on'] ? [values['fail-on']] : config.failOn);
  const jsonToStdout = values.json === '-';
  const quiet = values.quiet || jsonToStdout;
  const log = (m: string) => {
    if (!quiet) process.stderr.write(process.stderr.isTTY ? `\x1b[2m${m}\x1b[0m\n` : `${m}\n`);
  };
  if (configFile) log(`Using config ${configFile}`);

  const report = await analyze({
    root,
    config,
    githubToken: values['github-token'] ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN,
    cacheDir: values['no-cache'] ? null : (values['cache-dir'] ?? DiskCache.defaultDir()),
    deep: !!values.deep,
    bundle: !!values.bundle,
    prodOnly: !!values.prod,
    ecosystems: parseEcosystems(values.ecosystem),
    noSearch: !!values['no-search'],
    version: VERSION,
    log,
  });

  if (values.json) {
    const json = JSON.stringify(report, null, 2);
    if (jsonToStdout) process.stdout.write(json + '\n');
    else {
      writeFileSync(values.json, json);
      log(`JSON report: ${path.resolve(values.json)}`);
    }
  }
  if (values.sarif) {
    writeFileSync(values.sarif, renderSarif(report));
    log(`SARIF report: ${path.resolve(values.sarif)}`);
  }
  if (!values['no-html']) {
    const htmlFile = values.html ?? 'dephealth-report.html';
    writeFileSync(htmlFile, renderHtml(report));
    if (!quiet) process.stderr.write(`HTML report: ${path.resolve(htmlFile)}\n`);
  }
  if (!quiet) process.stdout.write(renderText(report, Number(values.top ?? 10)) + '\n');

  if (values.ci) {
    const violations = evaluate(report, rules);
    const out = jsonToStdout ? process.stderr : process.stdout;
    if (violations.length) {
      out.write(`\nCI check failed (${rules.join(', ')}):\n`);
      for (const v of violations) out.write(`  ✗ ${v.rule}: ${v.message}${v.packages.length ? ` — ${v.packages.slice(0, 8).join(', ')}${v.packages.length > 8 ? ', …' : ''}` : ''}\n`);
      return 1;
    }
    out.write(`\nCI check passed (${rules.join(', ')})\n`);
  }
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: Error) => {
    process.stderr.write(`dephealth: ${err.message}\n`);
    process.exitCode = 2;
  },
);
