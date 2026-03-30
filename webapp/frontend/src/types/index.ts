export interface FlowNodeData {
  id: string;
  type: string;
  name: string;
  description?: string;
  technique_id?: string;
  tactic_id?: string;
  tactic_name?: string;
  source_excerpt?: string;
  confidence?: string;
  command_line?: string;
  tool_types?: string[];
  cve_id?: string;
  cvss_score?: number;
  operator?: string;
}

export interface AnalyzeResponse {
  nodes: Array<{ id: string; type: string; data: FlowNodeData; position: { x: number; y: number } }>;
  edges: Array<{ id: string; source: string; target: string; label?: string }>;
  stix_bundle?: Record<string, unknown>;
  afb_data?: Record<string, unknown>;
  stats: Record<string, unknown>;
}

export interface UploadResponse {
  filename: string;
  file_type: string;
  text_content: string;
  stix_bundle?: Record<string, unknown>;
  char_count: number;
}

export type RuleFocus =
  | 'technique'
  | 'tool'
  | 'malware'
  | 'vulnerability'
  | 'asset'
  | 'infrastructure'
  | 'other';

/** Backend rule / query channels (major SIEM, EDR-style, IDS, portable). */
export type RuleOutputFormat =
  | 'sigma'
  | 'splunk_spl'
  | 'elastic_eql'
  | 'elastic_kql'
  | 'microsoft_sentinel_kql'
  | 'crowdstrike_fql'
  | 'chronicle_yaral'
  | 'qradar_aql'
  | 'yara'
  | 'suricata';

export interface DetectionRules {
  technique_id: string;
  technique_name: string;
  mitre_tactic?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  behavioral_summary?: string;
  data_sources?: string;
  false_positives?: string;
  implementation_guide?: string;
  sigma?: string;
  splunk_spl?: string;
  elastic_eql?: string;
  elastic_kql?: string;
  microsoft_sentinel_kql?: string;
  crowdstrike_fql?: string;
  chronicle_yaral?: string;
  qradar_aql?: string;
  yara?: string;
  suricata?: string;
}

/** Payload for bulk rule API (matches backend RuleRequest). */
export interface RuleBulkItem {
  technique_name: string;
  technique_id?: string | null;
  tactic_name?: string;
  description?: string;
  source_excerpt?: string;
  focus: RuleFocus;
  /** If omitted, backend uses legacy default (sigma, yara, suricata). */
  output_formats?: RuleOutputFormat[];
  /** Optional pasted excerpt or notes to ground generation (not stored on the graph). */
  additional_context?: string | null;
}

export type AppState = 'upload' | 'analyzing' | 'viewing';
