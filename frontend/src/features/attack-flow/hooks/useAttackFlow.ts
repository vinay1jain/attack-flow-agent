/**
 * Phase 2 stub — hook for fetching and managing attack flow state.
 */
export function useAttackFlow(_reportId: string) {
  // TODO: Phase 2 — implement with React Query, polling, cache
  return {
    flow: null,
    isLoading: false,
    error: null,
    generate: async () => {},
    refetch: async () => {},
  };
}
