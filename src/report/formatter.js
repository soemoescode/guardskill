const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
const CSI = String.fromCharCode(27) + '[';

const sorted = f => [...f].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

// Every string in a finding can come from the scanned tree: a config value, a
// directory name, a script name. None of it reaches a terminal or a report file
// with its control characters intact - a path called
// "vendor<ESC>[2K\rNo findings" would otherwise erase the line it appears on and
// write the attacker's text over it.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
export function sanitise(text) {
  return String(text ?? '').replace(CONTROL, '\uFFFD').replace(/[\r\n]+/g, ' ');
}
const md = s => sanitise(s).replace(/\|/g, '\\|').replace(/`/g, "'");

export function counts(findings) {
  return findings.reduce((a, f) => ({ ...a, [f.severity]: (a[f.severity] || 0) + 1 }), {});
}

export function formatText(result, { color = false } = {}) {
  const c = (code, s) => (color ? `${CSI}${code}m${s}${CSI}0m` : s);
  const out = [];
  out.push(c('1', 'GuardSkill') + ' - git execution-vector scan (read-only)');
  out.push(`Path: ${sanitise(result.rootPath)}`);

  if (!result.scanned) {
    out.push('', `Not scanned: ${sanitise(result.reason)}`);
    return out.join('\n');
  }

  out.push(`Git configurations inspected: ${result.targetCount}   Directories walked: ${result.dirsVisited}`);
  const incomplete = (result.incompleteReasons ?? []);
  if (incomplete.length) {
    out.push(c('33', 'Incomplete:') + ' part of this tree was not inspected -');
    for (const reason of incomplete) out.push(`  · ${sanitise(reason)}`);
  }
  out.push('');

  if (result.findings.length === 0) {
    out.push(incomplete.length
      ? c('33', 'No findings in the part of the tree that was inspected.') + ' This is not a clean result.'
      : c('32', 'No findings.') + ' Nothing was changed - this scan only reads.');
    return out.join('\n');
  }

  for (const f of sorted(result.findings)) {
    const tint = f.severity === 'critical' ? '31' : f.severity === 'high' ? '33' : '36';
    out.push(`${c(tint, '[' + LABEL[f.severity] + ']')} ${sanitise(f.location)} - ${sanitise(f.title)}`);
    out.push(`  what   ${sanitise(f.explanation)}`);
    out.push(`  found  ${sanitise(f.evidence)}`);
    if (f.remediation) out.push(`  do     ${sanitise(f.remediation)}`);
    out.push('');
  }

  const n = counts(result.findings);
  out.push(['critical', 'high', 'medium', 'low'].map(s => `${n[s] || 0} ${s}`).join(', ') + '.');
  out.push('Nothing was changed - this scan only reads.');
  if (result.findings.some(f => f.ruleId === 'bare-repo-in-tree')) {
    out.push('Tip: git config --global safe.bareRepository explicit  stops git from discovering bare repositories automatically.');
  }
  return out.join('\n');
}

export function formatMarkdown(result) {
  const out = ['# GuardSkill scan report', '', `**Path:** \`${md(result.rootPath)}\``, ''];
  if (!result.scanned) { out.push(`Not scanned: ${md(result.reason)}`); return out.join('\n'); }
  out.push(`Git configurations inspected: ${result.targetCount}`, '');

  const incomplete = (result.incompleteReasons ?? []);
  if (incomplete.length) {
    out.push('> **Incomplete scan.** Part of this tree was not inspected:', '');
    for (const reason of incomplete) out.push(`> - ${md(reason)}`);
    out.push('');
  }

  if (result.findings.length === 0) {
    out.push(incomplete.length
      ? 'No findings in the part of the tree that was inspected. This is not a clean result.'
      : 'No findings. Nothing was changed - this scan only reads.');
    return out.join('\n');
  }

  out.push('| Severity | Location | Finding | Evidence |', '|---|---|---|---|');
  for (const f of sorted(result.findings)) {
    out.push(`| ${LABEL[f.severity]} | \`${md(f.location)}\` | ${md(f.title)} | \`${md(f.evidence)}\` |`);
  }
  out.push('', '## Details', '');
  for (const f of sorted(result.findings)) {
    out.push(`### ${LABEL[f.severity]} - ${md(f.title)}`, '',
      `**Location:** \`${md(f.location)}\``, '', `**Found:** \`${md(f.evidence)}\``, '', md(f.explanation), '');
    if (f.remediation) out.push(`**What to do:** ${md(f.remediation)}`, '');
  }
  out.push('_Nothing was changed - this scan only reads._');
  return out.join('\n');
}

/**
 * JSON keeps the raw values - it is not a terminal - but escapes the escape
 * character itself so a consumer that prints a field cannot be surprised either.
 */
export function formatJson(result, version, status) {
  const escapeEsc = s => String(s ?? '').replace(/\u001b/g, '\\u001b');
  return JSON.stringify({
    tool: 'guardskill',
    version,
    schemaVersion: 1,
    path: result.rootPath,
    status,
    scanned: result.scanned,
    reason: result.reason ?? null,
    targetCount: result.targetCount,
    dirsVisited: result.dirsVisited,
    truncated: result.truncated,
    incompleteReasons: result.incompleteReasons ?? [],
    summary: counts(result.findings),
    findings: sorted(result.findings).map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      title: escapeEsc(f.title),
      explanation: escapeEsc(f.explanation),
      remediation: escapeEsc(f.remediation ?? ''),
      location: escapeEsc(f.location),
      evidence: escapeEsc(f.evidence),
    })),
  }, null, 2);
}
