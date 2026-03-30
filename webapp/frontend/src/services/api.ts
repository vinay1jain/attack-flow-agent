import type {
  AnalyzeResponse,
  DetectionRules,
  RuleBulkItem,
  RuleOutputFormat,
  UploadResponse,
} from '../types';

const API = '/api';

export interface HealthResponse {
  status: string;
  version: string;
  llm_ready: boolean;
  llm_model: string;
  extraction_model: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

function formatFastApiDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((x) => (typeof x === 'object' && x !== null && 'msg' in x
        ? String((x as { msg: string }).msg)
        : JSON.stringify(x)))
      .join(' ');
  }
  return 'Request failed';
}

export async function uploadFile(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}/upload`, { method: 'POST', body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(formatFastApiDetail(err.detail) || 'Upload failed');
  }
  return res.json();
}

export async function analyzeText(
  text_content: string,
  filename?: string,
  stix_bundle?: Record<string, unknown>,
): Promise<AnalyzeResponse> {
  const body: Record<string, unknown> = { text_content, filename };
  if (stix_bundle) body.stix_bundle = stix_bundle;

  const res = await fetch(`${API}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(formatFastApiDetail(err.detail) || 'Analysis failed');
  }
  return res.json();
}

export async function generateRules(params: {
  technique_name: string;
  technique_id?: string | null;
  tactic_name?: string;
  description?: string;
  source_excerpt?: string;
  focus?: string;
  output_formats?: RuleOutputFormat[];
  additional_context?: string | null;
}): Promise<DetectionRules> {
  const res = await fetch(`${API}/rules/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Rule generation failed');
  return res.json();
}

export async function downloadBulkRules(techniques: RuleBulkItem[]): Promise<Blob> {
  const res = await fetch(`${API}/rules/bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ techniques }),
  });
  if (!res.ok) throw new Error('Bulk rule generation failed');
  return res.blob();
}
