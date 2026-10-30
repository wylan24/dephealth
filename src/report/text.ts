import type { Report } from '../types.ts';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c(1);
const dim = c(2);
const red = c(31);
const yellow = c(33);
const green = c(32);

const scoreColor = (n: number) => (n >= 80 ? green : n >= 50 ? yellow : red);

/** Short terminal summary; the HTML report has the details. */
export function renderText(r: Report, top = 10): string {
  const s = r.summary;
  const v = s.vulnerabilities;
  const lines = [
    '',
    bold(`dephealth — ${r.workspaces[0]?.name ?? r.root}`) +
      dim(` (${s.packages} packages, ${s.direct} direct, ${r.workspaces.length} workspace${r.workspaces.length > 1 ? 's' : ''}; ${r.lockfiles.map((l) => `${l.ecosystem}: ${l.kind}`).join(', ')})`),
    `  Average score  ${scoreColor(s.averageScore)(String(s.averageScore))}/100     Libyears ${s.totalLibyear}`,
    `  Insecure ${s.byCategory.insecure} ${dim(`(${v.critical} critical, ${v.high} high, ${v.moderate} moderate, ${v.low} low)`)}   Abandoned ${s.byCategory.abandoned}   Outdated ${s.byCategory.outdated}   Heavy ${s.byCategory.weight}`,
  ];
  if (s.duplicates.length) lines.push(dim(`  ${s.duplicates.length} packages locked at more than one version`));
  if (r.incomplete.length) {
    lines.push('', red(bold('  Results are incomplete, so a clean result here does not mean all clear:')));
    for (const reason of r.incomplete) lines.push(red(`  ! ${reason}`));
  }
  if (r.actions.length) {
    lines.push('', bold(`Top ${Math.min(top, r.actions.length)} actions`));
    r.actions.slice(0, top).forEach((a, i) => {
      const eco = r.ecosystems.length > 1 ? dim(`${a.ecosystem} `) : '';
      lines.push(`  ${String(i + 1).padStart(2)}. ${eco}${bold(a.package)} ${dim(`[${a.category}]`)} ${a.title}`);
      lines.push(dim(`      ${a.detail}`));
    });
  } else if (!r.incomplete.length) {
    lines.push('', green('  No actions needed.'));
  }
  for (const w of r.warnings) lines.push(yellow(`  ! ${w}`));
  return lines.join('\n');
}
