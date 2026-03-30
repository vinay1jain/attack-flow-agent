# Attack Flow Agent

AI-powered attack flow generation from threat intelligence reports: MITRE ATT&CK–aware flows, STIX-oriented exports, and React Flow–style graphs for analysis and visualization.

## Try the standalone web app (v1)

For a **browser-only demo** (upload STIX/PDF, visualize flows, generate detection rules), use **[`webapp/`](webapp/README.md)**. **You supply your own LLM API key** via server environment variables (`OPENAI_API_KEY` in `webapp/backend/.env` or your cloud secret store). Nothing is hardcoded in the repo, and **do not** put keys in `VITE_*` frontend variables—they would be exposed to anyone who loads the site.

## What it does

The service ingests threat intelligence **reports** (via API integration or the standalone uploader) and, at a high level:

1. Fetches report and related intelligence objects when connected to an upstream platform.
2. Assembles a narrative from structured data when prose is thin.
3. Runs the `ttp_chainer` pipeline (DSPy / LLM) to extract techniques, tools, and chains.
4. Produces STIX 2.1 bundles, MITRE AFB-oriented JSON, and graph data for React Flow–style UIs.
5. Persists results and can notify upstream systems via configured callbacks (see integration code).

## Architecture

```text
Client UI → Backend proxy (your app) → Attack Flow Agent (FastAPI) → LLM / local model
                                              ↓
                                ttp_chainer (DSPy) + LangGraph pipeline
```

For integrated deployments, implement a thin authenticated proxy as in [docs/PROXY_INTEGRATION.md](docs/PROXY_INTEGRATION.md). End users and browsers should **not** call the agent directly in production.

## Quick start

### Prerequisites

- Python **3.11+**
- An LLM provider (OpenAI, Anthropic, or local Ollama) configured for LiteLLM
- Optional: an existing threat-intel deployment for full API integration (see `agent/.env.example`)

### Setup

```bash
cd attack-flow-agent
cp agent/.env.example agent/.env
# Edit agent/.env: platform URL / HMAC fields if integrating, LLM keys, TTP_CHAINER_PATH

cd agent
pip install -r requirements.txt
# or: pip install -e ".[dev]"   if using pyproject editable install

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Ensure `PYTHONPATH` includes the `agent` package root when running `uvicorn` from `agent/` (as above, `app.main:app`).

### Docker

```bash
docker compose up -d
docker compose logs -f agent
```

Compose mounts `./agent` and loads `agent/.env`.

### Verify

```bash
curl -s http://localhost:8000/api/v1/health | jq .
```

Authenticated routes need `X-Tenant-Id` and HMAC query params; see [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

## API endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/attack-flow/generate` | Queue generation for a report |
| `GET` | `/api/v1/attack-flow/jobs/{id}` | Job status and result |
| `GET` | `/api/v1/attack-flow/report/{id}` | Latest flow for a report |
| `GET` | `/api/v1/attack-flow/{flow_id}/export/{fmt}` | Export `stix`, `afb`, or `flowviz` |
| `GET` | `/api/v1/health` | Health check (no auth) |

Full schemas, errors, and auth: [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

## Project structure

```text
attack-flow-agent/
├── webapp/                     # Standalone UI + API (v1 demo; BYOK for LLM)
├── agent/                      # FastAPI service
│   ├── app/
│   │   ├── main.py             # App factory, middleware, exception handlers
│   │   ├── config.py           # pydantic-settings
│   │   ├── api/                # Routes, middleware, schemas
│   │   ├── core/               # Pipeline, narrative, TLP, jobs, errors
│   │   ├── integrations/       # Upstream API client, ttp_chainer adapter
│   │   └── models/             # Jobs, flow domain types
│   ├── tests/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── pyproject.toml
├── frontend/                   # React module (feature scaffolding)
│   └── src/features/attack-flow/
├── infra/                      # Terraform (e.g. AWS ECS Fargate)
├── docs/                       # Proxy spec, API reference
└── docker-compose.yml
```

## Configuration

Environment variables are documented in [agent/.env.example](agent/.env.example). Important groups:

| Variable | Description | Default (typical) |
| --- | --- | --- |
| `LLM_MODEL` | LiteLLM model id for main reasoning | `openai/gpt-4o` |
| `LLM_EXTRACTION_MODEL` | Lighter model for extraction-style steps | `openai/gpt-4o-mini` |
| `LLM_LOCAL_MODEL` | Local model for strict TLP (e.g. TLP:RED) | `ollama/llama3` |
| `*_BASE_URL`, `*_ACCESS_ID`, `*_SECRET_KEY`, `*_VERIFY_SSL` | Optional upstream API + HMAC (see `.env.example` names) | required when integrating |
| `RATE_LIMIT_PER_TENANT` | Max `generate` calls per tenant per window | `20` |
| `RATE_LIMIT_WINDOW_SECONDS` | Window length in seconds | `3600` |
| `NARRATIVE_TOKEN_BUDGET` / `NARRATIVE_MIN_SDOS` | Narrative assembly limits | see `.env.example` |
| `TTP_CHAINER_PATH` | Filesystem path to ttp_chainer | `/app/ttp_chainer` |
| `AGENT_HOST` / `AGENT_PORT` / `AGENT_LOG_LEVEL` | Bind and logging | `0.0.0.0`, `8000`, `INFO` |

## Deployment

- **Development:** `docker compose` or local `uvicorn` as above.
- **Production:** See [infra/](infra/) for Terraform targeting AWS ECS Fargate; run the agent in the same trust zone as your application servers, with no public ingress to the agent port.

## Documentation

- [docs/PROXY_INTEGRATION.md](docs/PROXY_INTEGRATION.md) — Backend proxy contract.
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) — Agent HTTP API.

## Publishing on GitHub

The project is meant to ship **without secrets**: only `*.env.example` files, never committed `.env` or real API keys. Before the first push, skim `git status` and avoid adding `*.tfvars` with real values.

**First push (after `git` is initialized in this folder):**

1. On GitHub: **New repository** → choose a name (e.g. `attack-flow-agent`). Do **not** add a README, `.gitignore`, or license if this tree already contains them.
2. Add the remote and push `main` and the **`v1.0.0`** tag:

```bash
cd /path/to/attack-flow-agent
git remote add origin https://github.com/<YOUR_USER_OR_ORG>/<REPO_NAME>.git
git branch -M main
git push -u origin main
git push origin v1.0.0
```

Use SSH instead if you prefer: `git@github.com:<YOUR_USER_OR_ORG>/<REPO_NAME>.git`. GitHub will prompt for sign-in (browser, PAT, or SSH key) depending on your setup.

On GitHub, **Releases → Draft a new release** from tag `v1.0.0` if you want release notes for others trying the webapp.

## License

Proprietary — Cyware Technologies.
