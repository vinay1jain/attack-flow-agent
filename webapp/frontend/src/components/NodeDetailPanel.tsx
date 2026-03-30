import { useState, useEffect, useMemo } from 'react';
import {
  Box, Typography, IconButton, Button, Divider, Chip, CircularProgress, Paper,
  FormControl, InputLabel, Select, MenuItem, Alert, Tabs, Tab, FormGroup,
  FormControlLabel, Checkbox, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Stack,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ShieldIcon from '@mui/icons-material/Shield';
import LaunchIcon from '@mui/icons-material/Launch';
import type { FlowNodeData, DetectionRules, RuleFocus, RuleOutputFormat } from '../types';
import { generateRules } from '../services/api';
import RulesViewer from './RulesViewer';
import { focusFromNodeType } from '../utils/ruleFocus';
import { downloadDetectionRulesBundle } from '../utils/downloadRules';
import {
  ALL_OUTPUT_FORMATS,
  DEFAULT_OUTPUT_FORMATS,
  optionsByGroup,
  type RuleOutputGroup,
} from '../utils/ruleOutputs';

interface Props {
  node: FlowNodeData;
  onClose: () => void;
  cachedRules: DetectionRules | null;
  onRulesSaved: (nodeId: string, rules: DetectionRules) => void;
}

export default function NodeDetailPanel({ node, onClose, cachedRules, onRulesSaved }: Props) {
  const [panelTab, setPanelTab] = useState(0);
  const [rules, setRules] = useState<DetectionRules | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focus, setFocus] = useState<RuleFocus>(() => focusFromNodeType(node.type));
  const [outputFormats, setOutputFormats] = useState<Set<RuleOutputFormat>>(
    () => new Set(DEFAULT_OUTPUT_FORMATS),
  );
  const [downloadPromptOpen, setDownloadPromptOpen] = useState(false);
  const [pendingRulesForDownload, setPendingRulesForDownload] = useState<DetectionRules | null>(null);
  const [additionalContext, setAdditionalContext] = useState('');

  // Reset tab / context only when switching nodes — not when `cachedRules` updates after generate.
  useEffect(() => {
    setError(null);
    setFocus(focusFromNodeType(node.type));
    setPanelTab(0);
    setAdditionalContext('');
  }, [node.id, node.type]);

  useEffect(() => {
    setRules(cachedRules);
  }, [cachedRules]);

  const ruleContextFields = useMemo(() => {
    const ok = (s?: string | null) => !!(s && String(s).trim());
    return [
      { label: 'Node label', present: ok(node.name) },
      { label: 'MITRE technique ID', present: ok(node.technique_id) },
      { label: 'Tactic name', present: ok(node.tactic_name) },
      { label: 'Description', present: ok(node.description) },
      { label: 'Report evidence', present: ok(node.source_excerpt) },
      { label: 'Command line', present: ok(node.command_line) },
    ];
  }, [node]);

  const thinGrounding = useMemo(() => {
    const hasNarrative = !!(node.description?.trim() || node.source_excerpt?.trim());
    const hasExtra = !!additionalContext.trim();
    return !hasNarrative && !hasExtra;
  }, [node.description, node.source_excerpt, additionalContext]);

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

  const mitreUrl = node.technique_id
    ? `https://attack.mitre.org/techniques/${node.technique_id.replace('.', '/')}`
    : null;

  const handleGenerateRules = async () => {
    const formats = ALL_OUTPUT_FORMATS.filter((f) => outputFormats.has(f));
    if (formats.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const result = await generateRules({
        technique_name: node.name,
        technique_id: node.technique_id || undefined,
        tactic_name: node.tactic_name || undefined,
        description: node.description || undefined,
        source_excerpt: node.source_excerpt || undefined,
        focus,
        output_formats: formats,
        additional_context: additionalContext.trim() || undefined,
      });
      setRules(result);
      onRulesSaved(node.id, result);
      setPendingRulesForDownload(result);
      setDownloadPromptOpen(true);
      setPanelTab(1);
    } catch {
      setError('Could not generate rules. Check the API key and try again.');
    }
    setLoading(false);
  };

  const closeDownloadPrompt = () => {
    setDownloadPromptOpen(false);
    setPendingRulesForDownload(null);
  };

  const confirmDownload = () => {
    if (pendingRulesForDownload) {
      downloadDetectionRulesBundle(pendingRulesForDownload, node.name);
    }
    closeDownloadPrompt();
  };

  return (
    <Paper sx={{
      position: 'absolute', top: 0, right: 0, bottom: 0, width: 500, zIndex: 10,
      bgcolor: 'background.paper', borderLeft: '1px solid', borderColor: 'divider',
      overflow: 'hidden', display: 'flex', flexDirection: 'column',
    }}>
      <Box sx={{
        p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
        borderBottom: '1px solid', borderColor: 'divider',
      }}>
        <Box sx={{ minWidth: 0, pr: 1 }}>
          <Chip label={node.type} size="small" sx={{ mb: 1, textTransform: 'uppercase', fontSize: 10 }} />
          <Typography variant="h6" sx={{ lineHeight: 1.3 }}>{node.name}</Typography>
          {node.technique_id && (
            <Typography variant="body2" sx={{ color: 'primary.main', fontFamily: "'JetBrains Mono', monospace", mt: 0.5 }}>
              {node.technique_id}
              {mitreUrl && (
                <IconButton size="small" href={mitreUrl} target="_blank" sx={{ ml: 0.5 }}>
                  <LaunchIcon sx={{ fontSize: 14 }} />
                </IconButton>
              )}
            </Typography>
          )}
        </Box>
        <IconButton onClick={onClose} size="small"><CloseIcon /></IconButton>
      </Box>

      <Tabs
        value={panelTab}
        onChange={(_, v) => setPanelTab(v)}
        sx={{ px: 2, pt: 1, borderBottom: 1, borderColor: 'divider', minHeight: 40 }}
      >
        <Tab label="Details" sx={{ textTransform: 'none', minHeight: 40 }} />
        <Tab label="Detection rules" sx={{ textTransform: 'none', minHeight: 40 }} />
      </Tabs>

      <Box sx={{ p: 2, flex: 1, overflow: 'auto' }}>
        {panelTab === 0 && (
          <>
            {node.tactic_name && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">TACTIC</Typography>
                <Typography variant="body2">{node.tactic_name}</Typography>
              </Box>
            )}

            {node.description && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">DESCRIPTION</Typography>
                <Typography variant="body2" sx={{ mt: 0.5, lineHeight: 1.6 }}>{node.description}</Typography>
              </Box>
            )}

            {node.source_excerpt && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">EVIDENCE FROM REPORT</Typography>
                <Paper variant="outlined" sx={{ p: 1.5, mt: 0.5, bgcolor: 'rgba(88,166,255,0.05)', borderColor: 'primary.dark' }}>
                  <Typography variant="body2" sx={{ fontStyle: 'italic', lineHeight: 1.6 }}>{node.source_excerpt}</Typography>
                </Paper>
              </Box>
            )}

            {node.command_line && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">COMMAND LINE</Typography>
                <Paper variant="outlined" sx={{ p: 1, mt: 0.5, fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                  {node.command_line}
                </Paper>
              </Box>
            )}

            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Open the <strong>Detection rules</strong> tab to choose SIEM, EDR, and IDS technologies. Generation is <strong>behavior-first</strong> (TTPs, telemetry) with MITRE mapping and tuning notes.
            </Typography>
          </>
        )}

        {panelTab === 1 && (
          <>
            <Typography variant="subtitle2" sx={{ mb: 0.75 }}>Sent to rule generator</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
              Only these node fields (plus your optional text below) are sent to the API. The long analyst pack in the response is model-generated from this context.
            </Typography>
            <Stack direction="row" flexWrap="wrap" useFlexGap spacing={0.5} sx={{ mb: 1.5 }}>
              {ruleContextFields.map((row) => (
                <Chip
                  key={row.label}
                  size="small"
                  variant="outlined"
                  label={`${row.label}: ${row.present ? 'Present' : 'Missing'}`}
                  color={row.present ? 'success' : 'default'}
                  sx={{ fontSize: 11 }}
                />
              ))}
            </Stack>

            {thinGrounding && (
              <Alert severity="warning" sx={{ mb: 1.5 }}>
                No description, report evidence, or extra context yet — output will lean on the label, MITRE ID (if any), and model priors. Paste a short excerpt from the report below for tighter rules.
              </Alert>
            )}

            <TextField
              label="Additional context (optional)"
              placeholder="Paste 1–3 sentences from the report, IOCs, or host details. Not saved on the graph."
              value={additionalContext}
              onChange={(e) => setAdditionalContext(e.target.value)}
              fullWidth
              multiline
              minRows={2}
              maxRows={6}
              size="small"
              sx={{ mb: 2 }}
            />

            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
              Select platforms for <strong>native</strong> queries. The model also returns Sigma, MITRE mapping, data sources, false-positive notes, and a deployment guide (from the context above).
            </Typography>

            <FormControl fullWidth size="small" sx={{ mb: 2 }}>
              <InputLabel id="rule-focus-label">What to detect</InputLabel>
              <Select
                labelId="rule-focus-label"
                label="What to detect"
                value={focus}
                onChange={(e) => setFocus(e.target.value as RuleFocus)}
              >
                <MenuItem value="technique">MITRE technique / procedure</MenuItem>
                <MenuItem value="tool">Tool or software</MenuItem>
                <MenuItem value="malware">Malware</MenuItem>
                <MenuItem value="vulnerability">Vulnerability / CVE-style</MenuItem>
                <MenuItem value="asset">Asset or victim resource</MenuItem>
                <MenuItem value="infrastructure">Infrastructure / host / network</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>

            <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Technologies to generate</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
              At least one. Uncheck stacks you do not need to shorten the response.
            </Typography>
            {(() => {
              const byGroup = optionsByGroup();
              const order: RuleOutputGroup[] = [
                'Portable', 'SIEM & analytics', 'EDR & cloud', 'Network', 'Endpoint artifacts',
              ];
              return order.map((g) => (
                <Box key={g} sx={{ mb: 1.5 }}>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 0.5, fontSize: 12 }}>
                    {g}
                  </Typography>
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
                        label={(
                          <Box>
                            <Typography variant="body2">{opt.label}</Typography>
                            <Typography variant="caption" color="text.secondary" display="block">{opt.hint}</Typography>
                          </Box>
                        )}
                        sx={{ alignItems: 'flex-start', mb: 0.25 }}
                      />
                    ))}
                  </FormGroup>
                </Box>
              ));
            })()}

            <Button
              variant="contained"
              startIcon={loading ? <CircularProgress size={16} /> : <ShieldIcon />}
              onClick={handleGenerateRules}
              disabled={loading || outputFormats.size === 0}
              fullWidth
              sx={{ mb: 2, background: 'linear-gradient(135deg, #6366f1, #8b5cf6)' }}
            >
              {loading ? 'Generating…' : rules ? 'Regenerate rules' : 'Generate detection rules'}
            </Button>

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

            {rules && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                  Saved for this node while you explore the graph. Use Download for a file anytime.
                </Typography>
                <RulesViewer rules={rules} />
              </>
            )}
          </>
        )}
      </Box>

      <Dialog open={downloadPromptOpen} onClose={closeDownloadPrompt} maxWidth="xs" fullWidth>
        <DialogTitle>Rules ready</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            Generation finished. Your analyst pack and platform rules are on the Detection rules tab. Download the combined text file now?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDownloadPrompt}>Not now</Button>
          <Button variant="contained" onClick={confirmDownload}>Download</Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}
