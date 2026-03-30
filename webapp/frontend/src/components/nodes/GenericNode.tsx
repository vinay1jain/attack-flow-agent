import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import { Handle, Position } from 'reactflow';

const TYPE_COLORS: Record<string, string> = {
  tool: '#f59e0b',
  malware: '#ef4444',
  asset: '#10b981',
  infrastructure: '#6366f1',
  vulnerability: '#ec4899',
  url: '#06b6d4',
};

const TYPE_ICONS: Record<string, string> = {
  tool: '\u2692',
  malware: '\u2620',
  asset: '\uD83D\uDCBB',
  infrastructure: '\uD83C\uDF10',
  vulnerability: '\u26A0',
  url: '\uD83D\uDD17',
};

function GenericNode({ data, selected }: NodeProps) {
  const color = TYPE_COLORS[data.type] || '#6b7280';
  const icon = TYPE_ICONS[data.type] || '\u25CF';
  return (
    <div style={{
      padding: 14, borderRadius: 10, minWidth: 180, maxWidth: 260,
      background: '#0d1117',
      border: `2px solid ${selected ? color : '#30363d'}`,
      boxShadow: selected ? `0 0 16px ${color}33` : '0 2px 8px rgba(0,0,0,0.3)',
      color: '#e6edf3', transition: 'all 0.2s',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: color, width: 8, height: 8 }} />
      <div style={{ fontSize: 10, fontWeight: 600, color, textTransform: 'uppercase', marginBottom: 6 }}>
        {icon} {data.type}
      </div>
      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{data.name}</div>
      {data.description && (
        <div style={{ fontSize: 11, color: '#8b949e', lineHeight: 1.4 }}>
          {data.description.length > 80 ? data.description.slice(0, 80) + '...' : data.description}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: color, width: 8, height: 8 }} />
    </div>
  );
}

export default memo(GenericNode);
