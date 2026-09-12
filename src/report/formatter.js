import { createHash } from 'node:crypto';

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

  out.push(`Git configurations inspected: ${result.targetCount}   `
    + `Agent settings files: ${result.agentFileCount ?? 0}   `
    + `Directories walked: ${result.dirsVisited}`);
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
  out.push(`Git configurations inspected: ${result.targetCount}`,
    `Agent settings files inspected: ${result.agentFileCount ?? 0}`, '');

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
    agentFileCount: result.agentFileCount ?? 0,
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

// ---------------------------------------------------------------------- SARIF

// SARIF is what turns a scan into something a team keeps. GitHub reads this file
// and puts every finding in the repository's Security tab, with the file, the
// line and a status per finding - so a result is something to resolve rather
// than a red cross to rerun. A tool that only sets an exit code is removed from
// the pipeline the first time it is noisy; one that is visible is argued with
// instead, which is the better failure mode.
//
// Mapping choices, stated because they are choices:
//   critical, high -> error      medium -> warning      low -> note
// and `security-severity`, which is what GitHub actually sorts on, is set from
// the same four levels rather than from a CVSS score - GuardSkill does not
// compute one, and inventing a number to fill the field would be a claim.

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SARIF_SECURITY_SEVERITY = { critical: '9.0', high: '7.0', medium: '5.0', low: '3.0' };

/** "path/to/file:12" -> { uri, startLine }. A location with no line is still a location. */
function sarifLocation(location) {
  const text = sanitise(location);
  const m = text.match(/^(.*):(\d+)$/);
  const uri = (m ? m[1] : text).replace(/\\/g, '/').replace(/^\.\//, '');
  return { uri: uri || '.', startLine: m ? Number(m[2]) : undefined };
}

const defaultFingerprint = text => createHash('sha256').update(text).digest('hex').slice(0, 32);

export function formatSarif(result, version, fingerprint = defaultFingerprint) {
  const findings = sorted(result.findings);

  const rules = [];
  const ruleIndex = new Map();
  for (const f of findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push({
      id: f.ruleId,
      name: f.ruleId.replace(/(^|-)([a-z])/g, (_, d, c) => c.toUpperCase()),
      shortDescription: { text: sanitise(f.title) },
      fullDescription: { text: sanitise(f.explanation) },
      help: {
        text: `${sanitise(f.explanation)}\n\n${sanitise(f.remediation ?? '')}`.trim(),
        markdown: `${sanitise(f.explanation)}\n\n**What to do:** ${sanitise(f.remediation ?? '')}`.trim(),
      },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] ?? 'note' },
      properties: {
        tags: ['security', 'supply-chain', 'coding-agent'],
        'security-severity': SARIF_SECURITY_SEVERITY[f.severity] ?? '3.0',
        guardskillSeverity: f.severity,
      },
    });
  }

  const results = findings.map(f => {
    const { uri, startLine } = sarifLocation(f.location);
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: SARIF_LEVEL[f.severity] ?? 'note',
      message: { text: `${sanitise(f.title)} - ${sanitise(f.evidence)}` },
      locations: [{
        physicalLocation: {
          // No uriBaseId: the URIs are already relative to the scanned root, and
          // GitHub rejects a base id that is not declared in originalUriBaseIds.
          artifactLocation: { uri },
          ...(startLine ? { region: { startLine } } : {}),
        },
      }],
      partialFingerprints: { guardskill: fingerprint(`${f.ruleId}|${f.location}|${f.evidence}`) },
      properties: { guardskillSeverity: f.severity },
    };
  });

  // An incomplete scan must stay visible here too. Without these notifications a
  // reader of the Security tab would see "no more findings" and have no way to
  // know that part of the tree was never opened.
  const notifications = (result.incompleteReasons ?? []).map(reason => ({
    level: 'warning',
    message: { text: `Part of this tree was not inspected: ${sanitise(reason)}` },
    descriptor: { id: 'guardskill/incomplete' },
  }));

  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'GuardSkill',
          informationUri: 'https://github.com/soemoescode/guardskill',
          version,
          semanticVersion: version,
          rules,
        },
      },
      invocations: [{
        executionSuccessful: result.scanned === true,
        ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
      }],
      results,
    }],
  }, null, 2);
}
