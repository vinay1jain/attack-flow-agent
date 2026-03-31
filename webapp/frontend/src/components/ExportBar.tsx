import { useState } from 'react';
import { Box, Button, Menu, MenuItem, ListItemIcon, ListItemText } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ImageIcon from '@mui/icons-material/Image';
import DataObjectIcon from '@mui/icons-material/DataObject';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ShieldIcon from '@mui/icons-material/Shield';
import { toPng } from 'html-to-image';
import { saveAs } from 'file-saver';
import type { AnalyzeResponse } from '../types';
import RulesBulkDialog from './RulesBulkDialog';

interface Props {
  data: AnalyzeResponse;
}

export default function ExportBar({ data }: Props) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [rulesDialogOpen, setRulesDialogOpen] = useState(false);
  const openRulesDialog = () => {
    setAnchor(null);
    setRulesDialogOpen(true);
  };

  const handleExportPng = async () => {
    setAnchor(null);
    const el = document.querySelector('.react-flow') as HTMLElement;
    if (!el) return;
    // Ensure the whole graph is visible before capture (not just current viewport).
    const fitBtn = document.querySelector('.react-flow__controls-fitview') as HTMLButtonElement | null;
    if (fitBtn && !fitBtn.disabled) {
      fitBtn.click();
      await new Promise((r) => setTimeout(r, 180));
    }
    const dataUrl = await toPng(el, { backgroundColor: '#0d1117', pixelRatio: 2 });
    saveAs(dataUrl, 'attack-flow.png');
  };

  const handleExportStix = () => {
    setAnchor(null);
    if (data.stix_bundle) {
      const blob = new Blob([JSON.stringify(data.stix_bundle, null, 2)], { type: 'application/json' });
      saveAs(blob, 'attack-flow-stix.json');
    }
  };

  const handleExportAfb = () => {
    setAnchor(null);
    if (data.afb_data) {
      const blob = new Blob([JSON.stringify(data.afb_data, null, 2)], { type: 'application/json' });
      saveAs(blob, 'attack-flow.afb');
    }
  };

  /** React Flow–compatible graph (nodes + edges) for reuse or tooling. */
  const handleExportFlowJson = () => {
    setAnchor(null);
    const payload = {
      format: 'attack-flow-agent',
      version: 1,
      nodes: data.nodes,
      edges: data.edges,
      stats: data.stats ?? {},
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
    saveAs(blob, 'attack-flow.json');
  };

  return (
    <Box sx={{
      position: 'absolute', bottom: 16, left: '50%', transform: 'translateX(-50%)',
      zIndex: 5, display: 'flex', gap: 1,
      bgcolor: 'rgba(22,27,34,0.95)', borderRadius: 2, p: 1,
      border: '1px solid', borderColor: 'divider', backdropFilter: 'blur(8px)',
    }}>
      <Button size="small" variant="outlined" startIcon={<DownloadIcon />} onClick={(e) => setAnchor(e.currentTarget)}>
        Export
      </Button>
      <Button
        size="small"
        variant="contained"
        startIcon={<ShieldIcon />}
        onClick={openRulesDialog}
        sx={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)' }}
      >
        Central rules (ZIP)
      </Button>
      <RulesBulkDialog open={rulesDialogOpen} onClose={() => setRulesDialogOpen(false)} data={data} />
      <Menu
        anchorEl={anchor}
        open={Boolean(anchor)}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <MenuItem onClick={handleExportPng}>
          <ListItemIcon><ImageIcon fontSize="small" /></ListItemIcon>
          <ListItemText>PNG Image</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleExportFlowJson}>
          <ListItemIcon><AccountTreeIcon fontSize="small" /></ListItemIcon>
          <ListItemText primary="Attack flow (JSON)" secondary="React Flow nodes and edges" />
        </MenuItem>
        <MenuItem onClick={openRulesDialog}>
          <ListItemIcon><ShieldIcon fontSize="small" /></ListItemIcon>
          <ListItemText primary="Detection rules (analysis ZIP)" secondary="Choose technologies before generating" />
        </MenuItem>
        {data.stix_bundle && (
          <MenuItem onClick={handleExportStix}>
            <ListItemIcon><DataObjectIcon fontSize="small" /></ListItemIcon>
            <ListItemText>STIX 2.1 Bundle</ListItemText>
          </MenuItem>
        )}
        {data.afb_data && (
          <MenuItem onClick={handleExportAfb}>
            <ListItemIcon><DataObjectIcon fontSize="small" /></ListItemIcon>
            <ListItemText>MITRE AFB</ListItemText>
          </MenuItem>
        )}
      </Menu>
    </Box>
  );
}
