import { useState, useMemo, useEffect } from 'react';
import { Box, Tabs, Tab, IconButton, Tooltip, Paper, Button, Stack, Typography } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckIcon from '@mui/icons-material/Check';
import DownloadIcon from '@mui/icons-material/Download';
import type { DetectionRules } from '../types';
import { downloadDetectionRulesBundle, downloadDetectionRulesSeparateFiles } from '../utils/downloadRules';
import { buildRulesViewerTabs } from '../utils/ruleOutputs';

interface Props {
  rules: DetectionRules;
}

export default function RulesViewer({ rules }: Props) {
  const tabs = useMemo(() => buildRulesViewerTabs(rules), [rules]);
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setTab(0);
  }, [rules]);

  const safeTab = tabs.length === 0 ? 0 : Math.min(tab, tabs.length - 1);
  const current = tabs[safeTab];

  const handleCopy = async () => {
    if (!current) return;
    await navigator.clipboard.writeText(current.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (tabs.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No analyst or rule content was returned. Try regenerating with different technologies selected.
      </Typography>
    );
  }

  return (
    <Box>
      <Stack direction="row" spacing={1} sx={{ mb: 1, flexWrap: 'wrap' }}>
        <Button
          size="small"
          variant="outlined"
          startIcon={<DownloadIcon />}
          onClick={() => downloadDetectionRulesBundle(rules, rules.technique_name)}
        >
          Download pack (.txt)
        </Button>
        <Button
          size="small"
          variant="text"
          onClick={() => downloadDetectionRulesSeparateFiles(rules, rules.technique_name)}
        >
          Analyst .md + rule files
        </Button>
      </Stack>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1 }}>
        <Tabs
          value={safeTab}
          onChange={(_, v) => setTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            minHeight: 36,
            flex: 1,
            maxWidth: 'calc(100% - 40px)',
            '& .MuiTab-root': { minHeight: 36, py: 0, fontSize: 11, textTransform: 'none' },
          }}
        >
          {tabs.map((t) => (
            <Tab key={t.id} label={t.label} />
          ))}
        </Tabs>
        <Tooltip title={copied ? 'Copied!' : 'Copy tab'}>
          <IconButton size="small" onClick={handleCopy} sx={{ flexShrink: 0 }}>
            {copied ? <CheckIcon sx={{ fontSize: 16, color: 'success.main' }} /> : <ContentCopyIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        </Tooltip>
      </Box>
      <Paper variant="outlined" sx={{
        p: 2, mt: 1, maxHeight: 420, overflow: 'auto',
        bgcolor: '#010409', borderRadius: 1,
        fontFamily: "'JetBrains Mono', monospace", fontSize: 12, lineHeight: 1.6,
        whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: '#e6edf3',
      }}>
        {current.content}
      </Paper>
    </Box>
  );
}
