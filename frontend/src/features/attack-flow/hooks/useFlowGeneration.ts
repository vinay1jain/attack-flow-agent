/**
 * Phase 2 stub — hook for triggering and polling flow generation.
 */
export function useFlowGeneration() {
  // TODO: Phase 2 — implement generation trigger, job polling, progress tracking
  return {
    generate: async (_reportId: string) => {},
    jobStatus: null,
    isGenerating: false,
  };
}
