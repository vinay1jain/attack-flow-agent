import type { RuleFocus } from '../types';

/** Map graph node type to API `focus` (backend prompt). */
export function focusFromNodeType(nodeType: string): RuleFocus {
  switch (nodeType) {
    case 'tool':
      return 'tool';
    case 'malware':
      return 'malware';
    case 'vulnerability':
      return 'vulnerability';
    case 'asset':
      return 'asset';
    case 'infrastructure':
      return 'infrastructure';
    case 'url':
      return 'other';
    case 'action':
    default:
      return 'technique';
  }
}
