import { useState, useCallback, useRef } from 'react';
import {
  Box, Typography, Button, Paper, LinearProgress, Alert, Chip, Stack,
  Tabs, Tab, TextField,
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SecurityIcon from '@mui/icons-material/Security';
import DescriptionIcon from '@mui/icons-material/Description';
import ContentPasteIcon from '@mui/icons-material/ContentPaste';
import type { AnalyzeResponse, UploadResponse } from '../types';
import { uploadFile, analyzeText } from '../services/api';

interface Props {
  onUploadComplete: (data: UploadResponse) => void;
  onAnalysisComplete: (data: AnalyzeResponse) => void;
  onAnalyzing: () => void;
  isAnalyzing: boolean;
  uploadData: UploadResponse | null;
  error: string | null;
  onError: (e: string | null) => void;
}

export default function UploadView({
  onUploadComplete, onAnalysisComplete, onAnalyzing, isAnalyzing, uploadData, error, onError,
}: Props) {
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState('');
  const [tab, setTab] = useState(0);
  const [pastedText, setPastedText] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(async (file: File) => {
    onError(null);
    setUploading(true);
    setProgress('Parsing file...');
    try {
      const data = await uploadFile(file);
      onUploadComplete(data);
      setProgress('File parsed successfully. Ready to analyze.');
      setUploading(false);
    } catch (err: any) {
      onError(err.message || 'Upload failed');
      setUploading(false);
      setProgress('');
    }
  }, [onUploadComplete, onError]);

  const handlePasteSubmit = useCallback(() => {
    const trimmed = pastedText.trim();
    if (!trimmed) return;
    onError(null);
    const synthetic: UploadResponse = {
      filename: 'pasted-text',
      file_type: 'text',
      text_content: trimmed,
      stix_bundle: undefined,
      char_count: trimmed.length,
    };
    onUploadComplete(synthetic);
  }, [pastedText, onUploadComplete, onError]);

  const handleAnalyze = useCallback(async () => {
    if (!uploadData) return;
    onAnalyzing();
    const mode = uploadData.stix_bundle ? 'Converting STIX bundle' : 'Running AI analysis — extracting techniques';
    setProgress(`${mode}, building attack graph...`);
    try {
      const result = await analyzeText(
        uploadData.text_content,
        uploadData.filename,
        uploadData.stix_bundle as Record<string, unknown> | undefined,
      );
      onAnalysisComplete(result);
    } catch (err: any) {
      onError(err.message || 'Analysis failed');
      setProgress('');
    }
  }, [uploadData, onAnalyzing, onAnalysisComplete, onError]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', p: 3 }}>
      <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
      <Typography
        variant="h4"
        gutterBottom
        sx={{
          background: 'linear-gradient(135deg, #58a6ff, #f78166)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}
      >
        Attack Flow Analyzer
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4, maxWidth: 600, textAlign: 'center' }}>
        Upload a threat intelligence report or paste advisory text to automatically generate
        an interactive attack flow and detection rules.
      </Typography>

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{ mb: 2, '& .MuiTab-root': { color: '#8b949e' }, '& .Mui-selected': { color: '#58a6ff' } }}
        TabIndicatorProps={{ sx: { bgcolor: '#58a6ff' } }}
      >
        <Tab icon={<CloudUploadIcon />} label="Upload File" iconPosition="start" />
        <Tab icon={<ContentPasteIcon />} label="Paste Text" iconPosition="start" />
      </Tabs>

      {tab === 0 && (
        <Paper
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => !uploading && !isAnalyzing && fileRef.current?.click()}
          sx={{
            width: '100%', maxWidth: 600, p: 6, textAlign: 'center',
            cursor: uploading || isAnalyzing ? 'default' : 'pointer',
            border: '2px dashed',
            borderColor: dragOver ? 'primary.main' : 'divider',
            bgcolor: dragOver ? 'rgba(88,166,255,0.05)' : 'background.paper',
            borderRadius: 3, transition: 'all 0.2s',
            '&:hover': { borderColor: uploading || isAnalyzing ? 'divider' : 'primary.main' },
          }}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".json,.stix,.pdf,.txt,.md,.csv,.log"
            hidden
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />
          <CloudUploadIcon sx={{ fontSize: 56, color: dragOver ? 'primary.main' : 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>Drop your report here</Typography>
          <Typography variant="body2" color="text.secondary">
            STIX 2.1 Bundle (.json), PDF Report (.pdf), or Text File (.txt)
          </Typography>
          <Stack direction="row" spacing={1} justifyContent="center" sx={{ mt: 2 }}>
            <Chip label="STIX JSON" size="small" variant="outlined" />
            <Chip label="PDF" size="small" variant="outlined" />
            <Chip label="TXT" size="small" variant="outlined" />
          </Stack>
        </Paper>
      )}

      {tab === 1 && (
        <Paper sx={{ width: '100%', maxWidth: 600, p: 3, borderRadius: 3 }}>
          <TextField
            multiline
            rows={10}
            fullWidth
            placeholder="Paste your threat advisory, vulnerability report, or any security content here..."
            value={pastedText}
            onChange={(e) => setPastedText(e.target.value)}
            disabled={isAnalyzing}
            sx={{
              '& .MuiOutlinedInput-root': {
                bgcolor: 'rgba(0,0,0,0.2)',
                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                fontSize: 13,
                '& fieldset': { borderColor: '#30363d' },
                '&:hover fieldset': { borderColor: '#58a6ff' },
                '&.Mui-focused fieldset': { borderColor: '#58a6ff' },
              },
              '& .MuiInputBase-input': { color: '#e6edf3' },
            }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            {pastedText.length > 0 ? `${pastedText.length.toLocaleString()} characters` : 'Minimum ~100 characters recommended'}
          </Typography>
          <Button
            variant="contained"
            fullWidth
            size="large"
            onClick={handlePasteSubmit}
            disabled={pastedText.trim().length < 50 || isAnalyzing}
            sx={{
              mt: 2, py: 1.5, fontSize: '1rem',
              background: 'linear-gradient(135deg, #1f6feb, #58a6ff)',
              '&:hover': { background: 'linear-gradient(135deg, #58a6ff, #79c0ff)' },
              '&.Mui-disabled': { background: '#21262d', color: '#484f58' },
            }}
          >
            Use This Text
          </Button>
        </Paper>
      )}

      {uploadData && !isAnalyzing && (
        <Paper sx={{ mt: 3, p: 3, width: '100%', maxWidth: 600, borderRadius: 2 }}>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <DescriptionIcon color="primary" />
            <Box>
              <Typography variant="subtitle2">{uploadData.filename}</Typography>
              <Typography variant="caption" color="text.secondary">
                {uploadData.file_type.toUpperCase()} — {uploadData.char_count.toLocaleString()} characters
              </Typography>
            </Box>
          </Stack>
          <Button
            variant="contained"
            fullWidth
            size="large"
            onClick={handleAnalyze}
            sx={{
              py: 1.5, fontSize: '1rem',
              background: 'linear-gradient(135deg, #238636, #2ea043)',
              '&:hover': { background: 'linear-gradient(135deg, #2ea043, #3fb950)' },
            }}
          >
            Analyze Attack Flow
          </Button>
        </Paper>
      )}

      {(uploading || isAnalyzing) && (
        <Box sx={{ mt: 3, width: '100%', maxWidth: 600 }}>
          <LinearProgress sx={{ mb: 1, borderRadius: 1 }} />
          <Typography variant="body2" color="text.secondary" textAlign="center">{progress}</Typography>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 3, maxWidth: 600, width: '100%' }}>{error}</Alert>
      )}

    </Box>
  );
}
