# Attack Flow Analyzer — Standalone Web App

Upload threat intelligence reports (STIX 2.1 JSON or PDF), visualize interactive attack flows, and generate detection rules (Sigma, YARA, Suricata).

**API keys:** This app does not ship with any provider credentials. Each operator sets **`OPENAI_API_KEY`** (or another LiteLLM-supported key) on the **backend** only—never in the frontend bundle or in git.

## Architecture

```
webapp/
├── backend/         FastAPI API server
│   ├── app/
│   │   ├── main.py      Routes & FastAPI app
│   │   ├── analyze.py   ttp_chainer pipeline + STIX→React Flow converter
│   │   ├── rules.py     LLM-powered detection rule generator
│   │   ├── upload.py    PDF/STIX file parsing
│   │   ├── schemas.py   Pydantic models
│   │   └── config.py    Settings (env vars)
│   ├── Dockerfile
│   ├── fly.toml
│   └── requirements.txt
└── frontend/        React + MUI + React Flow
    ├── src/
    │   ├── views/       UploadView, FlowView
    │   ├── components/  Nodes, detail panel, rules viewer, export bar
    │   ├── services/    API client
    │   └── utils/       Dagre layout
    ├── netlify.toml
    └── package.json
```

## Quick Start (Local Development)

### Prerequisites

- Python 3.11+
- Node.js 18+
- Access to `ttp_chainer` directory
- OpenAI API key (or other LiteLLM-compatible provider)

### 1. Backend

```bash
cd webapp/backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API key and ttp_chainer path

# Run
python -m app.main
# → API at http://localhost:8000
# → Docs at http://localhost:8000/docs
```

### 2. Frontend

```bash
cd webapp/frontend

npm install
npm run dev
# → UI at http://localhost:5173
```

The Vite dev server proxies `/api/*` to `localhost:8000` automatically.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/upload` | Upload PDF or STIX JSON file |
| POST | `/api/analyze` | Run attack flow analysis on text |
| POST | `/api/rules/generate` | Generate detection rules for one technique |
| POST | `/api/rules/bulk` | Generate rules for all techniques (ZIP download) |

## Deployment

### Frontend → Netlify

1. Push `webapp/frontend/` to a Git repo
2. Connect to Netlify
3. Build command: `npm run build`
4. Publish directory: `dist`
5. Update `netlify.toml` redirect URL to point to your deployed backend

### Backend → Fly.io

```bash
cd webapp/backend
fly launch    # follow prompts
fly secrets set OPENAI_API_KEY="(paste your key from the provider dashboard)"
fly secrets set TTP_CHAINER_PATH=/app/ttp_chainer
fly deploy
```

### Backend → Docker (any host)

```bash
cd webapp/backend
docker build -t attack-flow-api .
docker run -p 8000:8000 --env-file .env attack-flow-api
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | LLM provider API key (required; you create it; never commit) |
| `LLM_MODEL` | `openai/gpt-4o` | Model for rule generation |
| `LLM_EXTRACTION_MODEL` | `openai/gpt-4o-mini` | Model for TTP extraction |
| `TTP_CHAINER_PATH` | — | Absolute path to ttp_chainer directory |
| `FRONTEND_URL` | `http://localhost:5173` | CORS allowed origin |
| `PORT` | `8000` | Backend port |
