import { useState, useCallback, useMemo } from 'react';
import ReactFlow, {
  Background, Controls, MiniMap, useNodesState, useEdgesState,
  type Node, type Edge, type NodeTypes,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Box, IconButton, Typography, Chip, Stack } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import type { AnalyzeResponse, DetectionRules, FlowNodeData } from '../types';
import ActionNode from '../components/nodes/ActionNode';
import GenericNode from '../components/nodes/GenericNode';
import OperatorNode from '../components/nodes/OperatorNode';
import NodeDetailPanel from '../components/NodeDetailPanel';
import ExportBar from '../components/ExportBar';
import { applyLayout } from '../utils/layout';

const nodeTypes: NodeTypes = {
  action: ActionNode,
  tool: GenericNode,
  malware: GenericNode,
  asset: GenericNode,
  infrastructure: GenericNode,
  vulnerability: GenericNode,
  url: GenericNode,
  AND_operator: OperatorNode,
  OR_operator: OperatorNode,
};

interface Props {
  data: AnalyzeResponse;
  onBack: () => void;
  rulesCache: Record<string, DetectionRules>;
  onPersistRules: (nodeId: string, rules: DetectionRules) => void;
}

export default function FlowView({ data, onBack, rulesCache, onPersistRules }: Props) {
  const layouted = useMemo(() => applyLayout(data.nodes as Node[], data.edges as Edge[]), [data]);
  const [nodes, , onNodesChange] = useNodesState(layouted.nodes);
  const [edges, , onEdgesChange] = useEdgesState(layouted.edges);
  const [selectedNode, setSelectedNode] = useState<FlowNodeData | null>(null);

  const onNodeClick = useCallback((_: unknown, node: Node) => {
    const d = node.data as FlowNodeData;
    setSelectedNode({ ...d, id: d.id || node.id });
  }, []);

  const stats = data.stats || {};

  if (!data.nodes.length) {
    return (
      <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', p: 3, bgcolor: 'background.default' }}>
        <IconButton onClick={onBack} size="small" sx={{ position: 'absolute', top: 16, left: 16 }}><ArrowBackIcon /></IconButton>
        <Typography variant="h6" gutterBottom>No attack flow was built</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 480, textAlign: 'center', mb: 2 }}>
          The model did not extract any nodes from this input. Try richer threat-intel text, use the Paste Text
          tab, or check that your OpenAI key and TTP_CHAINER_PATH are set on the backend. UTF-8 BOM and line
          endings are normalized when you upload .txt files.
        </Typography>
        <Chip label="0 nodes" size="small" variant="outlined" />
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100vh', position: 'relative' }}>
      <Box sx={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 5,
        display: 'flex', alignItems: 'center', gap: 2, p: 1.5, px: 2,
        bgcolor: 'rgba(13,17,23,0.9)', borderBottom: '1px solid', borderColor: 'divider',
        backdropFilter: 'blur(8px)',
      }}>
        <IconButton onClick={onBack} size="small"><ArrowBackIcon /></IconButton>
        <Typography variant="subtitle1" fontWeight={600}>Attack Flow</Typography>
        <Stack direction="row" spacing={1}>
          <Chip label={`${data.nodes.length} nodes`} size="small" variant="outlined" />
          <Chip label={`${data.edges.length} edges`} size="small" variant="outlined" />
          {(stats as any).elapsed_seconds != null && (
            <Chip label={`${(stats as any).elapsed_seconds}s`} size="small" variant="outlined" />
          )}
          {(stats as any).fallback && (
            <Chip
              label={(stats as any).fallback === 'llm_minigraph' ? 'LLM fallback graph' : 'TTP chain fallback'}
              size="small"
              color="warning"
              variant="outlined"
            />
          )}
        </Stack>
      </Box>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={nodeTypes}
        fitView
        defaultEdgeOptions={{
          style: { stroke: 'rgba(255,255,255,0.4)', strokeWidth: 1.5 },
          labelStyle: { fill: '#8b949e', fontSize: 11 },
          labelBgStyle: { fill: '#0d1117', fillOpacity: 0.9 },
        }}
        style={{ background: '#0d1117' }}
      >
        <Background color="#21262d" gap={20} size={1} />
        <Controls position="bottom-left" style={{ background: '#161b22', borderColor: '#30363d' }} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'action') return '#58a6ff';
            if (n.type === 'malware') return '#ef4444';
            if (n.type === 'tool') return '#f59e0b';
            return '#6b7280';
          }}
          style={{ background: '#0d1117', border: '1px solid #30363d' }}
        />
      </ReactFlow>

      {selectedNode && (
        <NodeDetailPanel
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
          cachedRules={rulesCache[selectedNode.id] ?? null}
          onRulesSaved={onPersistRules}
        />
      )}

      <ExportBar data={data} />
    </Box>
  );
}
