/**
 * Phase 2 stub — Attack Flow tab for the CTIX report detail page.
 * Will contain the FlowGraph, NodeDetailPanel, and ExportMenu.
 */
import { useState } from 'react';
import type { AttackFlowResult } from '../types/attack-flow';

interface AttackFlowTabProps {
  reportId: string;
  tenantId: string;
}

export default function AttackFlowTab({ reportId, tenantId }: AttackFlowTabProps) {
  const [_flow, _setFlow] = useState<AttackFlowResult | null>(null);

  // TODO: Phase 2 — implement useAttackFlow hook, FlowGraph, NodeDetailPanel, ExportMenu
  return (
    <div style={{ padding: 24, color: '#8b949e' }}>
      <p>Attack Flow visualization for report <strong>{reportId}</strong></p>
      <p>Tenant: {tenantId}</p>
      <p>Phase 2 — Interactive graph will render here.</p>
    </div>
  );
}
