export interface FlowNodeData {
  id: string;
  type: string;
  name: string;
  description?: string;
  technique_id?: string;
  tactic_id?: string;
  tactic_name?: string;
  source_excerpt?: string;
  confidence?: 'low' | 'medium' | 'high';
  command_line?: string;
  tool_types?: string[];
  cve_id?: string;
  cvss_score?: number;
  indicator_type?: string;
  indicator_value?: string;
  operator?: 'AND' | 'OR';
}

export interface FlowNode {
  id: string;
  type: string;
  data: FlowNodeData;
  position: { x: number; y: number };
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface AttackFlowResult {
  flow_id: string;
  report_id: string;
  tenant_id: string;
  nodes: FlowNode[];
  edges: FlowEdge[];
  generated_at: string;
  llm_model?: string;
  total_tokens?: number;
  tlp_marking?: string;
}

export interface JobStatus {
  job_id: string;
  report_id: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  stage?: string;
  progress_message?: string;
  created_at: string;
  result?: AttackFlowResult;
}

export type ValidNodeType =
  | 'action'
  | 'tool'
  | 'malware'
  | 'asset'
  | 'infrastructure'
  | 'url'
  | 'vulnerability'
  | 'AND_operator'
  | 'OR_operator';

export const TACTIC_NAMES: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
};
