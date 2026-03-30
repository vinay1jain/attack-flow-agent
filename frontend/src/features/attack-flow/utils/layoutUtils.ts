import dagre from 'dagre';
import type { Node, Edge } from 'reactflow';

const LAYOUT_CONFIG = {
  rankdir: 'TB',
  ranksep: 200,
  nodesep: 150,
  edgesep: 60,
  marginx: 80,
  marginy: 80,
  nodeWidth: 220,
  nodeHeight: 130,
} as const;

export function getLayoutedElements(nodes: Node[], edges: Edge[]) {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({
    rankdir: LAYOUT_CONFIG.rankdir,
    ranksep: LAYOUT_CONFIG.ranksep,
    nodesep: LAYOUT_CONFIG.nodesep,
    edgesep: LAYOUT_CONFIG.edgesep,
    marginx: LAYOUT_CONFIG.marginx,
    marginy: LAYOUT_CONFIG.marginy,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, {
      width: LAYOUT_CONFIG.nodeWidth,
      height: LAYOUT_CONFIG.nodeHeight,
    });
  });

  edges.forEach((edge) => {
    const sourceNode = nodes.find((n) => n.id === edge.source);
    const targetNode = nodes.find((n) => n.id === edge.target);
    const weight =
      sourceNode?.type === 'action' && targetNode?.type === 'action' ? 10 : 1;
    dagreGraph.setEdge(edge.source, edge.target, { weight });
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const pos = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: pos.x - LAYOUT_CONFIG.nodeWidth / 2,
        y: pos.y - LAYOUT_CONFIG.nodeHeight / 2,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}
