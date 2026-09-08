const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
const CSI = String.fromCharCode(27) + '[';

const sorted = f => [...f].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

export function counts(findings) {
  return findings.reduce((a, f) => ({ ...a, [f.severity]: (a[f.severity] || 0) + 1 }), {});
}

export function formatText(result, { color = false } = {}) {
  const c = (code, s) => (color ? `${CSI}${code}m${s}${CSI}0m` : s);
  const out = [];
  out.push(c('1', 'GuardSkill') + ' - git execution-vector scan (read-only)');
  out.push(`Path: ${result.rootPath}`);

  if (!result.scanned) {
    out.push('', `Not scanned: ${result.reason}`);
    return out.join('\n');
  }

  out.push(`Git configurations inspected: ${result.targetCount}   Directories walked: ${result.dirsVisited}`);
  if (result.truncated) out.push('Note: the walk hit its depth or size limit. Raise --max-depth for a complete scan.');
  out.push('');

  if (result.findings.length === 0) {
    out.push(c('32', 'No findings.') + ' Nothing was changed - this scan only reads.');
    return out.join('\n');
  }

  for (const f of sorted(result.findings)) {
    const tint = f.severity === 'critical' ? '31' : f.severity === 'high' ? '33' : '36';
    out.push(`${c(tint, '[' + LABEL[f.severity] + ']')} ${f.location} - ${f.title}`);
    out.push(`  what   ${f.explanation}`);
    out.push(`  found  ${f.evidence}`);
    if (f.remediation) out.push(`  do     ${f.remediation}`);
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
  const out = ['# GuardSkill scan report', '', `**Path:** \`${result.rootPath}\``, ''];
  if (!result.scanned) { out.push(`Not scanned: ${result.reason}`); return out.join('\n'); }
  out.push(`Git configurations inspected: ${result.targetCount}`, '');
  if (result.findings.length === 0) { out.push('No findings. Nothing was changed - this scan only reads.'); return out.join('\n'); }
  out.push('| Severity | Location | Finding | Evidence |', '|---|---|---|---|');
  for (const f of sorted(result.findings)) {
    out.push(`| ${LABEL[f.severity]} | \`${f.location}\` | ${f.title} | \`${f.evidence}\` |`);
  }
  out.push('', '## Details', '');
  for (const f of sorted(result.findings)) {
    out.push(`### ${LABEL[f.severity]} - ${f.title}`, '', `**Location:** \`${f.location}\``, '', f.explanation, '');
    if (f.remediation) out.push(`**What to do:** ${f.remediation}`, '');
  }
  out.push('_Nothing was changed - this scan only reads._');
  return out.join('\n');
}

export function formatJson(result, version) {
  return JSON.stringify({
    tool: 'guardskill',
    version,
    path: result.rootPath,
    scanned: result.scanned,
    reason: result.reason,
    targetCount: result.targetCount,
    dirsVisited: result.dirsVisited,
    truncated: result.truncated,
    summary: counts(result.findings),
    findings: sorted(result.findings),
  }, null, 2);
}
