import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import { Handle, Position } from 'reactflow';

function OperatorNode({ data }: NodeProps) {
  const label = data.type === 'AND_operator' ? 'AND' : 'OR';
  const color = data.type === 'AND_operator' ? '#6366f1' : '#f59e0b';
  return (
    <div style={{
      width: 52, height: 52, borderRadius: '50%',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: '#161b22', border: `2px solid ${color}`,
      color, fontWeight: 700, fontSize: 12,
      fontFamily: "'JetBrains Mono', monospace",
    }}>
      <Handle type="target" position={Position.Top} style={{ background: color, width: 6, height: 6 }} />
      {label}
      <Handle type="source" position={Position.Bottom} style={{ background: color, width: 6, height: 6 }} />
    </div>
  );
}

export default memo(OperatorNode);
