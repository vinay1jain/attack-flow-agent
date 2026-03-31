import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button, Box, Typography,
  Checkbox, FormControlLabel, FormGroup, TextField, MenuItem, Select, FormControl,
  InputLabel, Stack, Alert, CircularProgress, Divider, Chip,
} from '@mui/material';
import { saveAs } from 'file-saver';
import type { AnalyzeResponse, RuleBulkItem, RuleFocus, RuleOutputFormat, RuleOutputMode } from '../types';
import { downloadBulkRules } from '../services/api';
import { focusFromNodeType } from '../utils/ruleFocus';
import {
  ALL_OUTPUT_FORMATS,
  DEFAULT_OUTPUT_FORMATS,
  optionsByGroup,
  type RuleOutputGroup,
} from '../utils/ruleOutputs';

function isOperatorType(t: string): boolean {
  return t === 'AND_operator' || t === 'OR_operator';
}

interface CustomRow {
  key: string;
  name: string;
  focus: RuleFocus;
}

interface Props {
  open: boolean;
  onClose: () => void;
  data: AnalyzeResponse;
}

export default function RulesBulkDialog({ open, onClose, data }: Props) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [customRows, setCustomRows] = useState<CustomRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outputFormats, setOutputFormats] = useState<Set<RuleOutputFormat>>(
    () => new Set(DEFAULT_OUTPUT_FORMATS),
  );
  const [ruleOutputMode, setRuleOutputMode] = useState<RuleOutputMode>('per_node_zip');

  const eligibleNodes = useMemo(
    () => data.nodes.filter((n) => !isOperatorType(n.type)),
    [data.nodes],
  );

  useEffect(() => {
    if (!open) return;
    const ids = new Set<string>();
    for (const n of eligibleNodes) {
      const d = n.data;
      ids.add(d?.id || n.id);
    }
    setSelectedIds(ids);
    setCustomRows([]);
    setError(null);
    setOutputFormats(new Set(DEFAULT_OUTPUT_FORMATS));
    setRuleOutputMode('per_node_zip');
  }, [open, eligibleNodes]);

  const toggleFormat = (id: RuleOutputFormat) => {
    setOutputFormats((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        if (next.size > 1) next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const toggleId = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectTechniquesOnly = useCallback(() => {
    const ids = new Set<string>();
    for (const n of eligibleNodes) {
      const d = n.data;
      const isAction = (d?.type || n.type) === 'action';
      if (isAction && d?.technique_id) ids.add(d.id || n.id);
    }
    setSelectedIds(ids);
  }, [eligibleNodes]);

  const selectAll = useCallback(() => {
    setSelectedIds(new Set(eligibleNodes.map((n) => n.data?.id || n.id)));
  }, [eligibleNodes]);

  const selectNone = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const addCustomRow = useCallback(() => {
    setCustomRows((rows) => [
      ...rows,
      { key: `c-${Date.now()}-${rows.length}`, name: '', focus: 'tool' as RuleFocus },
    ]);
  }, []);

  const updateCustomRow = useCallback((key: string, patch: Partial<CustomRow>) => {
    setCustomRows((rows) => rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  }, []);

  const removeCustomRow = useCallback((key: string) => {
    setCustomRows((rows) => rows.filter((r) => r.key !== key));
  }, []);

  const buildPayload = useCallback((): RuleBulkItem[] => {
    const formats = ALL_OUTPUT_FORMATS.filter((f) => outputFormats.has(f));
    const items: RuleBulkItem[] = [];
    for (const n of eligibleNodes) {
      const id = n.data?.id || n.id;
      if (!selectedIds.has(id)) continue;
      const d = n.data;
      const nodeType = d?.type || n.type;
      items.push({
        technique_name: d.name,
        technique_id: d.technique_id || undefined,
        tactic_name: d.tactic_name,
        description: d.description,
        source_excerpt: d.source_excerpt,
        focus: focusFromNodeType(nodeType),
        output_formats: formats,
      });
    }
    for (const row of customRows) {
      const name = row.name.trim();
      if (!name) continue;
      items.push({
        technique_name: name,
        focus: row.focus,
        output_formats: formats,
      });
    }
    return items;
  }, [eligibleNodes, selectedIds, customRows, outputFormats]);
  const hasAnySelection = selectedIds.size > 0 || customRows.some((r) => r.name.trim().length > 0);

  const handleGenerate = async () => {
    const payload = buildPayload();
    if (payload.length === 0) {
      setError('Select at least one node or add a custom name.');
      return;
    }
    if (outputFormats.size === 0) {
      setError('Select at least one detection technology.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const blob = await downloadBulkRules(payload, ruleOutputMode);
      saveAs(blob, `detection-rules-analysis-${ruleOutputMode}.zip`);
      onClose();
    } catch {
      setError('Bulk generation failed. Check the API and try again.');
    }
    setLoading(false);
  };

  return (
    <Dialog open={open} onClose={loading ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Detection rules (analysis ZIP)</DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Generate a central detection pack for this analysis. Select the nodes to include and choose
          which technologies should be generated for every selected node.
        </Typography>

        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Technologies to include</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
          The same technologies are applied across selected nodes. The ZIP includes an
          <code>analyst_pack/</code> markdown file per item (MITRE mapping, data sources, false-positive tuning,
          implementation guide) plus vendor folders.
        </Typography>
        {(() => {
          const byGroup = optionsByGroup();
          const order: RuleOutputGroup[] = [
            'Portable', 'SIEM & analytics', 'EDR & cloud', 'Network', 'Endpoint artifacts',
          ];
          return (
            <Box sx={{ mb: 2, maxHeight: 220, overflow: 'auto', pr: 0.5 }}>
              {order.map((g) => (
                <Box key={g} sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>{g}</Typography>
                  <FormGroup>
                    {byGroup[g].map((opt) => (
                      <FormControlLabel
                        key={opt.id}
                        control={(
                          <Checkbox
                            checked={outputFormats.has(opt.id)}
                            onChange={() => toggleFormat(opt.id)}
                            size="small"
                          />
                        )}
                        label={<Typography variant="body2">{opt.label}</Typography>}
                      />
                    ))}
                  </FormGroup>
                </Box>
              ))}
            </Box>
          );
        })()}
        <FormControl fullWidth size="small" sx={{ mb: 2 }}>
          <InputLabel id="bulk-rule-output-mode-label">Output mode</InputLabel>
          <Select
            labelId="bulk-rule-output-mode-label"
            value={ruleOutputMode}
            label="Output mode"
            onChange={(e) => setRuleOutputMode(e.target.value as RuleOutputMode)}
          >
            <MenuItem value="per_node_zip">Per-node ZIP (legacy)</MenuItem>
            <MenuItem value="combined_per_technology">Combined per technology (single synthesized output)</MenuItem>
            <MenuItem value="merged_per_technology_file">Merged per technology file (per-node sections)</MenuItem>
          </Select>
        </FormControl>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
          <strong>Per-node ZIP:</strong> one file per node per technology.{' '}
          <strong>Combined per technology:</strong> one synthesized output per selected technology.{' '}
          <strong>Merged per technology file:</strong> one file per technology with per-node blocks.
        </Typography>

        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 2 }}>
          <Button size="small" variant="outlined" onClick={selectAll}>Select all</Button>
          <Button size="small" variant="outlined" onClick={selectNone}>Clear</Button>
          <Button size="small" variant="outlined" onClick={selectTechniquesOnly}>MITRE techniques only</Button>
        </Stack>

        <FormGroup sx={{ maxHeight: 240, overflow: 'auto', mb: 2 }}>
          {eligibleNodes.map((n) => {
            const d = n.data;
            const id = d?.id || n.id;
            const nodeType = d?.type || n.type;
            return (
              <FormControlLabel
                key={id}
                control={(
                  <Checkbox
                    checked={selectedIds.has(id)}
                    onChange={() => toggleId(id)}
                    size="small"
                  />
                )}
                label={(
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                    <Typography variant="body2">{d.name}</Typography>
                    <Chip label={nodeType} size="small" variant="outlined" sx={{ height: 20, fontSize: 10 }} />
                    {d.technique_id && (
                      <Typography variant="caption" color="primary.main" fontFamily="monospace">
                        {d.technique_id}
                      </Typography>
                    )}
                  </Box>
                )}
              />
            );
          })}
        </FormGroup>

        <Divider sx={{ my: 2 }} />
        <Typography variant="subtitle2" sx={{ mb: 1 }}>Custom target (optional)</Typography>
        {customRows.map((row) => (
          <Stack key={row.key} direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
            <TextField
              size="small"
              fullWidth
              placeholder="Name (e.g. Cobalt Strike, CVE-2024-…)"
              value={row.name}
              onChange={(e) => updateCustomRow(row.key, { name: e.target.value })}
            />
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel>Focus</InputLabel>
              <Select
                label="Focus"
                value={row.focus}
                onChange={(e) => updateCustomRow(row.key, { focus: e.target.value as RuleFocus })}
              >
                <MenuItem value="technique">Technique</MenuItem>
                <MenuItem value="tool">Tool</MenuItem>
                <MenuItem value="malware">Malware</MenuItem>
                <MenuItem value="vulnerability">Vulnerability</MenuItem>
                <MenuItem value="asset">Asset</MenuItem>
                <MenuItem value="infrastructure">Infrastructure</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>
            <Button size="small" color="inherit" onClick={() => removeCustomRow(row.key)}>Remove</Button>
          </Stack>
        ))}
        <Button size="small" onClick={addCustomRow}>+ Add custom target</Button>

        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleGenerate}
          disabled={loading || outputFormats.size === 0 || !hasAnySelection}
          startIcon={loading ? <CircularProgress size={16} /> : undefined}
        >
          {loading ? 'Generating…' : 'Generate analysis ZIP'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
