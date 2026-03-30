/** Same rules as backend `graph_connectivity.validate_attack_flow_connectivity`. */

export function isAttackFlowConnected(
  nodes: Array<{ id: string }>,
  edges: Array<{ source: string; target: string }>,
): boolean {
  const ids = new Set(
    nodes.map((n) => n.id).filter((id) => id != null && id !== ''),
  );
  if (ids.size <= 1) return true;
  if (!edges.length) return false;

  const adj = new Map<string, Set<string>>();
  ids.forEach((id) => adj.set(id, new Set()));
  for (const e of edges) {
    const s = String(e.source);
    const t = String(e.target);
    if (ids.has(s) && ids.has(t)) {
      adj.get(s)!.add(t);
      adj.get(t)!.add(s);
    }
  }

  const visited = new Set<string>();
  let components = 0;
  for (const id of ids) {
    if (visited.has(id)) continue;
    components += 1;
    const stack = [id];
    while (stack.length) {
      const u = stack.pop()!;
      if (visited.has(u)) continue;
      visited.add(u);
      for (const v of adj.get(u) ?? []) {
        if (!visited.has(v)) stack.push(v);
      }
    }
  }
  return components <= 1;
}
