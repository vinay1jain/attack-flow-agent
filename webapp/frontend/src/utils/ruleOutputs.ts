import type { DetectionRules, RuleOutputFormat } from '../types';

export type RuleOutputGroup = 'Portable' | 'SIEM & analytics' | 'EDR & cloud' | 'Network' | 'Endpoint artifacts';

/** User-facing labels: behavioral detections; CIM / ECS called out in backend prompt. */
export const RULE_OUTPUT_OPTIONS: {
  id: RuleOutputFormat;
  label: string;
  hint: string;
  group: RuleOutputGroup;
}[] = [
  {
    group: 'Portable',
    id: 'sigma',
    label: 'Sigma (YAML)',
    hint: 'Vendor-neutral rule; ECS-oriented fields; pair with native queries below.',
  },
  {
    group: 'SIEM & analytics',
    id: 'splunk_spl',
    label: 'Splunk SPL',
    hint: 'CIM-aligned fields; saved search / alert style.',
  },
  {
    group: 'SIEM & analytics',
    id: 'elastic_eql',
    label: 'Elastic EQL',
    hint: 'Elastic Security; ECS field names; sequences for behavior.',
  },
  {
    group: 'SIEM & analytics',
    id: 'elastic_kql',
    label: 'Elastic KQL',
    hint: 'Kibana Discover / building-block KQL; ECS.',
  },
  {
    group: 'SIEM & analytics',
    id: 'microsoft_sentinel_kql',
    label: 'Microsoft Sentinel KQL',
    hint: 'SecurityEvent, Device* tables, Entra / cloud as applicable.',
  },
  {
    group: 'SIEM & analytics',
    id: 'qradar_aql',
    label: 'IBM QRadar AQL',
    hint: 'QRadar offense / search style AQL.',
  },
  {
    group: 'EDR & cloud',
    id: 'crowdstrike_fql',
    label: 'CrowdStrike (Falcon query)',
    hint: 'Falcon LogScale / FQL-style behavioral telemetry.',
  },
  {
    group: 'EDR & cloud',
    id: 'chronicle_yaral',
    label: 'Google Chronicle YARA-L',
    hint: 'Chronicle detection rule (YARA-L 2.0 / UDM-oriented).',
  },
  {
    group: 'Network',
    id: 'suricata',
    label: 'Suricata / Snort',
    hint: 'Network IDS; behavioral protocol / flow patterns.',
  },
  {
    group: 'Endpoint artifacts',
    id: 'yara',
    label: 'YARA',
    hint: 'File / memory when relevant; otherwise comment-style N/A.',
  },
];

export const DEFAULT_OUTPUT_FORMATS: RuleOutputFormat[] = ['sigma', 'yara', 'suricata'];

export const ALL_OUTPUT_FORMATS: RuleOutputFormat[] = RULE_OUTPUT_OPTIONS.map((o) => o.id);

const GROUP_ORDER: RuleOutputGroup[] = [
  'Portable',
  'SIEM & analytics',
  'EDR & cloud',
  'Network',
  'Endpoint artifacts',
];

export function optionsByGroup(): Record<RuleOutputGroup, typeof RULE_OUTPUT_OPTIONS> {
  const acc = {} as Record<RuleOutputGroup, typeof RULE_OUTPUT_OPTIONS>;
  for (const g of GROUP_ORDER) {
    acc[g] = RULE_OUTPUT_OPTIONS.filter((o) => o.group === g);
  }
  return acc;
}

export function labelForOutputFormat(id: RuleOutputFormat): string {
  return RULE_OUTPUT_OPTIONS.find((o) => o.id === id)?.label ?? id;
}

/** Executable rule/query tabs only (not analyst prose). */
export function ruleBodyEntries(rules: DetectionRules): { key: RuleOutputFormat; content: string }[] {
  const out: { key: RuleOutputFormat; content: string }[] = [];
  for (const key of ALL_OUTPUT_FORMATS) {
    const v = rules[key];
    if (typeof v === 'string' && v.trim().length > 0) out.push({ key, content: v });
  }
  return out;
}

function isPlaceholderMeta(s: string | undefined): boolean {
  if (!s?.trim()) return true;
  return s.startsWith('(Not generated') || s.startsWith('Error:');
}

/** Tabs: implementation guide, ATT&CK & tuning, then each platform body. */
export function buildRulesViewerTabs(rules: DetectionRules): { id: string; label: string; content: string }[] {
  const tabs: { id: string; label: string; content: string }[] = [];

  if (rules.implementation_guide?.trim() && !isPlaceholderMeta(rules.implementation_guide)) {
    tabs.push({ id: 'guide', label: 'Implementation guide', content: rules.implementation_guide });
  }

  const ctx: string[] = [];
  if (rules.mitre_tactic?.trim() && !isPlaceholderMeta(rules.mitre_tactic)) {
    ctx.push(`## MITRE tactic\n${rules.mitre_tactic}`);
  }
  const mtid = rules.mitre_technique_id;
  const tid = (mtid && !isPlaceholderMeta(mtid)) ? mtid : (rules.technique_id || '');
  const tname = rules.mitre_technique_name;
  if ((tid && tid.trim()) || (tname && !isPlaceholderMeta(tname))) {
    ctx.push(`## MITRE technique\n**ID:** ${tid || '—'}\n**Name:** ${tname && !isPlaceholderMeta(tname) ? tname : '—'}`);
  }
  if (rules.behavioral_summary?.trim() && !isPlaceholderMeta(rules.behavioral_summary)) {
    ctx.push(`## Behavioral focus\n${rules.behavioral_summary}`);
  }
  if (rules.data_sources?.trim() && !isPlaceholderMeta(rules.data_sources)) {
    ctx.push(`## Data sources & telemetry\n${rules.data_sources}`);
  }
  if (rules.false_positives?.trim() && !isPlaceholderMeta(rules.false_positives)) {
    ctx.push(`## False positives & tuning\n${rules.false_positives}`);
  }
  if (ctx.length) {
    tabs.push({ id: 'context', label: 'ATT&CK & tuning', content: ctx.join('\n\n') });
  }

  for (const { key, content } of ruleBodyEntries(rules)) {
    tabs.push({ id: key, label: labelForOutputFormat(key), content });
  }

  return tabs;
}
