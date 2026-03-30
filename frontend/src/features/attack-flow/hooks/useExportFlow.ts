/**
 * Phase 2 stub — hook for exporting flows in various formats.
 */
export function useExportFlow() {
  // TODO: Phase 2 — implement export logic with format selection
  return {
    exportFlow: async (_flowId: string, _format: string) => {},
    isExporting: false,
  };
}
