import dagre from 'dagre';
import type { Node, Edge } from 'reactflow';

const CONFIG = {
  rankdir: 'TB' as const,
  ranksep: 200,
  nodesep: 150,
  edgesep: 60,
  marginx: 80,
  marginy: 80,
  nodeWidth: 240,
  nodeHeight: 140,
};

export function applyLayout(nodes: Node[], edges: Edge[]) {
  if (!nodes.length) {
    return { nodes: [], edges: edges ?? [] };
  }

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: CONFIG.rankdir,
    ranksep: CONFIG.ranksep,
    nodesep: CONFIG.nodesep,
    edgesep: CONFIG.edgesep,
    marginx: CONFIG.marginx,
    marginy: CONFIG.marginy,
  });

  nodes.forEach((n) =>
    g.setNode(n.id, { width: CONFIG.nodeWidth, height: CONFIG.nodeHeight }),
  );
  edges.forEach((e) => {
    const src = nodes.find((n) => n.id === e.source);
    const tgt = nodes.find((n) => n.id === e.target);
    const w = src?.type === 'action' && tgt?.type === 'action' ? 10 : 1;
    if (src && tgt) {
      g.setEdge(e.source, e.target, { weight: w });
    }
  });

  dagre.layout(g);

  return {
    nodes: nodes.map((n) => {
      const pos = g.node(n.id);
      const x = pos?.x ?? 0;
      const y = pos?.y ?? 0;
      return {
        ...n,
        position: {
          x: x - CONFIG.nodeWidth / 2,
          y: y - CONFIG.nodeHeight / 2,
        },
      };
    }),
    edges,
  };
}
