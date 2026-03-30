import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import { Handle, Position } from 'reactflow';

function ActionNode({ data, selected }: NodeProps) {
  return (
    <div style={{
      padding: 12,
      borderRadius: 8,
      background: selected ? '#1e3a5f' : '#0d1117',
      border: `2px solid ${selected ? '#3b82f6' : '#30363d'}`,
      color: '#fff',
      minWidth: 180,
      maxWidth: 260,
    }}>
      <Handle type="target" position={Position.Top} />
      <div style={{ fontSize: 10, color: '#8b949e', textTransform: 'uppercase', marginBottom: 4 }}>
        {data.tactic_name || 'technique'}
      </div>
      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
        {data.name}
      </div>
      {data.technique_id && (
        <div style={{ fontSize: 11, color: '#58a6ff' }}>
          {data.technique_id}
        </div>
      )}
      {data.description && (
        <div style={{ fontSize: 11, color: '#8b949e', marginTop: 4, lineHeight: 1.4 }}>
          {data.description.length > 120 ? data.description.slice(0, 120) + '...' : data.description}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

export default memo(ActionNode);
