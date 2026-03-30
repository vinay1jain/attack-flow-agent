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

function GenericNode({ data, selected }: NodeProps) {
  const color = TYPE_COLORS[data.type] || '#6b7280';
  return (
    <div style={{
      padding: 12,
      borderRadius: 8,
      background: '#0d1117',
      border: `2px solid ${selected ? color : '#30363d'}`,
      color: '#fff',
      minWidth: 160,
      maxWidth: 240,
    }}>
      <Handle type="target" position={Position.Top} />
      <div style={{ fontSize: 10, color, textTransform: 'uppercase', marginBottom: 4 }}>
        {data.type}
      </div>
      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
        {data.name}
      </div>
      {data.description && (
        <div style={{ fontSize: 11, color: '#8b949e', marginTop: 4, lineHeight: 1.4 }}>
          {data.description.length > 100 ? data.description.slice(0, 100) + '...' : data.description}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

export default memo(GenericNode);
