import { memo } from 'react';
import type { NodeProps } from 'reactflow';
import ActionNode from './ActionNode';
import GenericNode from './GenericNode';

function NodeFactory(props: NodeProps) {
  const { data } = props;

  if (data.type === 'action' || data.type === 'attack-action') {
    return <ActionNode {...props} />;
  }

  if (data.type === 'AND_operator' || data.type === 'OR_operator') {
    return <OperatorNode {...props} />;
  }

  return <GenericNode {...props} />;
}

function OperatorNode({ data }: NodeProps) {
  const label = data.type === 'AND_operator' ? 'AND' : 'OR';
  return (
    <div style={{
      padding: 8,
      borderRadius: '50%',
      background: '#1e293b',
      border: '2px solid #475569',
      color: '#fff',
      fontWeight: 700,
      width: 48,
      height: 48,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: 12,
    }}>
      {label}
    </div>
  );
}

export default memo(NodeFactory);
