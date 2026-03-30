import type { AnalyzeResponse, DetectionRules } from '../types';

const ACTIVE_FLOW = 'attackflow-active-v1';
const RULES_PREFIX = 'attackflow-rules-v1-';

/** Stable fingerprint for the current graph (rules cache key). */
export function deriveFlowKey(data: AnalyzeResponse): string {
  const nodePart = data.nodes.map((n) => n.id).sort().join('\u0001');
  const edgePart = data.edges
    .map((e) => `${e.source}\u0001${e.target}\u0001${e.label ?? ''}`)
    .sort()
    .join('\u0002');
  let h = 2166136261;
  const s = `${nodePart}\u0003${edgePart}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

function rulesStorageKey(flowKey: string): string {
  return `${RULES_PREFIX}${flowKey}`;
}

export function saveActiveFlowToSession(data: AnalyzeResponse): void {
  try {
    sessionStorage.setItem(ACTIVE_FLOW, JSON.stringify(data));
  } catch {
    /* quota / private mode */
  }
}

export function clearSessionAttackFlow(): void {
  try {
    sessionStorage.removeItem(ACTIVE_FLOW);
  } catch {
    /* ignore */
  }
}

export function loadActiveFlowFromSession(): AnalyzeResponse | null {
  try {
    const raw = sessionStorage.getItem(ACTIVE_FLOW);
    if (!raw) return null;
    const data = JSON.parse(raw) as AnalyzeResponse;
    if (!data?.nodes || !Array.isArray(data.nodes)) return null;
    return data;
  } catch {
    return null;
  }
}

export function saveRulesToSession(flowKey: string, rules: Record<string, DetectionRules>): void {
  try {
    if (Object.keys(rules).length === 0) {
      sessionStorage.removeItem(rulesStorageKey(flowKey));
    } else {
      sessionStorage.setItem(rulesStorageKey(flowKey), JSON.stringify(rules));
    }
  } catch {
    /* ignore */
  }
}

export function loadRulesFromSession(flowKey: string): Record<string, DetectionRules> | null {
  try {
    const raw = sessionStorage.getItem(rulesStorageKey(flowKey));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Record<string, DetectionRules>;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

export function clearRulesFromSession(flowKey: string): void {
  try {
    sessionStorage.removeItem(rulesStorageKey(flowKey));
  } catch {
    /* ignore */
  }
}
