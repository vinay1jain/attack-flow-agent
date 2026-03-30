import { useState, useCallback, useEffect } from 'react';
import { Box } from '@mui/material';
import type { AppState, AnalyzeResponse, DetectionRules, UploadResponse } from './types';
import UploadView from './views/UploadView';
import FlowView from './views/FlowView';
import {
  clearRulesFromSession,
  clearSessionAttackFlow,
  deriveFlowKey,
  loadActiveFlowFromSession,
  loadRulesFromSession,
  saveActiveFlowToSession,
  saveRulesToSession,
} from './utils/sessionAttackFlow';
import { isAttackFlowConnected } from './utils/graphConnectivity';

export default function App() {
  const [appState, setAppState] = useState<AppState>('upload');
  const [uploadData, setUploadData] = useState<UploadResponse | null>(null);
  const [flowData, setFlowData] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rulesByNodeId, setRulesByNodeId] = useState<Record<string, DetectionRules>>({});

  const onPersistRules = useCallback((nodeId: string, rules: DetectionRules) => {
    setRulesByNodeId((prev) => ({ ...prev, [nodeId]: rules }));
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('demo')) {
      setAppState('analyzing');
      fetch('/api/test-result')
        .then((r) => r.json())
        .then((data) => {
          const d = data as AnalyzeResponse;
          if (!isAttackFlowConnected(d.nodes, d.edges)) {
            setAppState('upload');
            setError('Demo graph is disconnected (no single linked flow). Use Upload / Paste to run a full analysis.');
            return;
          }
          setRulesByNodeId({});
          setFlowData(d);
          setAppState('viewing');
          saveActiveFlowToSession(d);
          clearRulesFromSession(deriveFlowKey(d));
        })
        .catch(() => setAppState('upload'));
      return;
    }
    const restored = loadActiveFlowFromSession();
    if (restored?.nodes?.length) {
      if (!isAttackFlowConnected(restored.nodes, restored.edges)) {
        clearSessionAttackFlow();
        setError('Your saved attack flow was disconnected and has been cleared. Run a new analysis.');
        return;
      }
      const k = deriveFlowKey(restored);
      const rules = loadRulesFromSession(k);
      setFlowData(restored);
      setRulesByNodeId(rules ?? {});
      setAppState('viewing');
    }
  }, []);

  const handleUploadComplete = useCallback((data: UploadResponse) => {
    setUploadData(data);
    setError(null);
  }, []);

  const handleAnalysisComplete = useCallback((data: AnalyzeResponse) => {
    setRulesByNodeId({});
    setFlowData(data);
    setAppState('viewing');
    setError(null);
    saveActiveFlowToSession(data);
    clearRulesFromSession(deriveFlowKey(data));
  }, []);

  const handleBack = useCallback(() => {
    setFlowData((current) => {
      if (current) clearRulesFromSession(deriveFlowKey(current));
      return null;
    });
    clearSessionAttackFlow();
    setAppState('upload');
    setUploadData(null);
    setRulesByNodeId({});
    setError(null);
    if (window.location.search) window.history.replaceState({}, '', '/');
  }, []);

  useEffect(() => {
    if (appState !== 'viewing' || !flowData) return;
    saveRulesToSession(deriveFlowKey(flowData), rulesByNodeId);
  }, [appState, flowData, rulesByNodeId]);

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
      {appState === 'upload' || appState === 'analyzing' ? (
        <UploadView
          onUploadComplete={handleUploadComplete}
          onAnalysisComplete={handleAnalysisComplete}
          onAnalyzing={() => setAppState('analyzing')}
          isAnalyzing={appState === 'analyzing'}
          uploadData={uploadData}
          error={error}
          onError={(e) => { setError(e); if (e) setAppState('upload'); }}
        />
      ) : (
        <FlowView
          data={flowData!}
          onBack={handleBack}
          rulesCache={rulesByNodeId}
          onPersistRules={onPersistRules}
        />
      )}
    </Box>
  );
}
