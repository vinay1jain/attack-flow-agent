import { saveAs } from 'file-saver';
import type { DetectionRules, RuleOutputFormat } from '../types';
import { labelForOutputFormat, ruleBodyEntries } from './ruleOutputs';

function slug(s: string) {
  return s.replace(/[^a-zA-Z0-9-_]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'rules';
}

const SEPARATE_EXT: Record<RuleOutputFormat, { mime: string; ext: string }> = {
  sigma: { mime: 'text/yaml;charset=utf-8', ext: '-sigma.yml' },
  splunk_spl: { mime: 'text/plain;charset=utf-8', ext: '-splunk.spl' },
  elastic_eql: { mime: 'text/plain;charset=utf-8', ext: '-elastic.eql' },
  elastic_kql: { mime: 'text/plain;charset=utf-8', ext: '-elastic.kql' },
  microsoft_sentinel_kql: { mime: 'text/plain;charset=utf-8', ext: '-sentinel.kql' },
  crowdstrike_fql: { mime: 'text/plain;charset=utf-8', ext: '-crowdstrike.fql' },
  chronicle_yaral: { mime: 'text/plain;charset=utf-8', ext: '-chronicle.yaral' },
  qradar_aql: { mime: 'text/plain;charset=utf-8', ext: '-qradar.aql' },
  yara: { mime: 'text/plain;charset=utf-8', ext: '.yar' },
  suricata: { mime: 'text/plain;charset=utf-8', ext: '.rules' },
};

function analystSections(rules: DetectionRules): string[] {
  const parts: string[] = [];
  const header = rules.technique_id
    ? `${rules.technique_name} (${rules.technique_id})`
    : rules.technique_name;
  parts.push(`# Detection analyst pack — ${header}`, '');
  if (rules.mitre_tactic) {
    parts.push('## MITRE tactic', '', rules.mitre_tactic, '');
  }
  if (rules.mitre_technique_id || rules.mitre_technique_name) {
    parts.push(
      '## MITRE technique',
      '',
      `**ID:** ${rules.mitre_technique_id ?? '—'}`,
      `**Name:** ${rules.mitre_technique_name ?? '—'}`,
      '',
    );
  }
  if (rules.behavioral_summary) {
    parts.push('## Behavioral summary', '', rules.behavioral_summary, '');
  }
  if (rules.data_sources) {
    parts.push('## Data sources & telemetry', '', rules.data_sources, '');
  }
  if (rules.false_positives) {
    parts.push('## False positives & tuning', '', rules.false_positives, '');
  }
  if (rules.implementation_guide) {
    parts.push('## Implementation guide', '', rules.implementation_guide, '');
  }
  return parts;
}

/** One text file: analyst metadata, then each selected platform. */
export function downloadDetectionRulesBundle(rules: DetectionRules, nameHint?: string) {
  const base = slug(nameHint || rules.technique_name || rules.technique_id || 'detection');
  const parts = [...analystSections(rules)];
  parts.push('---', '', '# Detection rules / queries', '');
  const entries = ruleBodyEntries(rules);
  for (const { key, content } of entries) {
    parts.push(`## ${labelForOutputFormat(key)}`, '', content, '');
  }
  if (entries.length === 0) {
    parts.push('(No platform rule bodies in this response.)', '');
  }
  saveAs(
    new Blob([parts.join('\n')], { type: 'text/plain;charset=utf-8' }),
    `${base}-detection-analyst-pack.txt`,
  );
}

/** One file per platform (only formats that have content). */
export function downloadDetectionRulesSeparateFiles(rules: DetectionRules, nameHint?: string) {
  const base = slug(nameHint || rules.technique_name || rules.technique_id || 'detection');
  const guide = analystSections(rules).join('\n');
  saveAs(
    new Blob([guide], { type: 'text/markdown;charset=utf-8' }),
    `${base}-analyst-pack.md`,
  );
  for (const { key, content } of ruleBodyEntries(rules)) {
    const { mime, ext } = SEPARATE_EXT[key];
    saveAs(new Blob([content], { type: mime }), `${base}${ext}`);
  }
}
