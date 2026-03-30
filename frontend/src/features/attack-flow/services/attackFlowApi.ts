import type { AttackFlowResult, JobStatus } from '../types/attack-flow';

const BASE_URL = '/api/v1/attack-flow';

interface GenerateResponse {
  job_id: string;
  status: string;
  message: string;
}

export async function generateAttackFlow(
  reportId: string,
  tenantId: string,
  forceRegenerate = false,
): Promise<GenerateResponse> {
  const res = await fetch(`${BASE_URL}/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-Id': tenantId,
    },
    body: JSON.stringify({
      report_id: reportId,
      force_regenerate: forceRegenerate,
    }),
  });
  if (!res.ok) throw new Error(`Generate failed: ${res.statusText}`);
  return res.json();
}

export async function getJobStatus(jobId: string): Promise<JobStatus> {
  const res = await fetch(`${BASE_URL}/jobs/${jobId}`);
  if (!res.ok) throw new Error(`Job status failed: ${res.statusText}`);
  return res.json();
}

export async function getFlowForReport(reportId: string): Promise<AttackFlowResult> {
  const res = await fetch(`${BASE_URL}/report/${reportId}`);
  if (!res.ok) throw new Error(`Flow fetch failed: ${res.statusText}`);
  return res.json();
}

export async function exportFlow(
  flowId: string,
  format: 'stix' | 'afb' | 'flowviz',
): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/${flowId}/export/${format}`);
  if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
  return res.blob();
}
