import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import { Handle, Position } from 'reactflow';

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access': '#ef4444',
  'Execution': '#f97316',
  'Persistence': '#eab308',
  'Privilege Escalation': '#84cc16',
  'Defense Evasion': '#22c55e',
  'Credential Access': '#14b8a6',
  'Discovery': '#06b6d4',
  'Lateral Movement': '#3b82f6',
  'Collection': '#6366f1',
  'Exfiltration': '#8b5cf6',
  'Command and Control': '#a855f7',
  'Impact': '#ec4899',
  'Resource Development': '#f43f5e',
  'Reconnaissance': '#fb923c',
};

function ActionNode({ data, selected }: NodeProps) {
  const tacticColor = TACTIC_COLORS[data.tactic_name || ''] || '#58a6ff';
  return (
    <div style={{
      padding: 14, borderRadius: 10, minWidth: 200, maxWidth: 280,
      background: selected ? '#1c2333' : '#0d1117',
      border: `2px solid ${selected ? tacticColor : '#30363d'}`,
      boxShadow: selected ? `0 0 20px ${tacticColor}33` : '0 2px 8px rgba(0,0,0,0.3)',
      color: '#e6edf3', transition: 'all 0.2s',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: tacticColor, width: 8, height: 8 }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 10, fontWeight: 600, color: tacticColor, textTransform: 'uppercase', letterSpacing: 0.5 }}>
          {data.tactic_name || 'technique'}
        </span>
        {data.confidence && (
          <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: 'rgba(255,255,255,0.1)', color: '#8b949e' }}>
            {data.confidence}
          </span>
        )}
      </div>
      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4, lineHeight: 1.3 }}>{data.name}</div>
      {data.technique_id && (
        <div style={{ fontSize: 11, color: '#58a6ff', fontFamily: "'JetBrains Mono', monospace", marginBottom: 4 }}>
          {data.technique_id}
        </div>
      )}
      {data.description && (
        <div style={{ fontSize: 11, color: '#8b949e', lineHeight: 1.4, marginTop: 4 }}>
          {data.description.length > 100 ? data.description.slice(0, 100) + '...' : data.description}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: tacticColor, width: 8, height: 8 }} />
    </div>
  );
}

export default memo(ActionNode);
