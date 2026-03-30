# CTIX Attack Flow Agent

AI-powered attack flow generation from threat intelligence reports for the Cyware Threat Intelligence eXchange (CTIX) platform.

## Try the standalone web app (v1)

For a **browser-only demo** (upload STIX/PDF, visualize flows, generate detection rules), use **[`webapp/`](webapp/README.md)**. **You supply your own LLM API key** via server environment variables (`OPENAI_API_KEY` in `webapp/backend/.env` or your cloud secret store). Nothing is hardcoded in the repo, and **do not** put keys in `VITE_*` frontend variables—they would be exposed to anyone who loads the site.

## What it does

The agent takes a CTIX threat intelligence report and produces a MITRE ATT&CK–aware attack flow suitable for analysis and visualization. At a high level it:

1. Fetches the report and related intelligence objects from CTIX.
2. Assembles a narrative from structured data when prose is thin.
3. Runs the `ttp_chainer` pipeline (DSPy / LLM) to extract techniques, tools, and chains.
4. Produces STIX 2.1 bundles, MITRE AFB-oriented JSON, and graph data for React Flow–style UIs.
5. Persists results and can notify CTIX via configured callbacks (see integration code).

## Architecture

```text
CTIX Frontend → CTIX Backend (Django proxy) → Attack Flow Agent (FastAPI) → LLM / local model
                                                      ↓
                                            ttp_chainer (DSPy) + LangGraph pipeline
```

Backend teams should implement the Django proxy as specified in [docs/PROXY_INTEGRATION.md](docs/PROXY_INTEGRATION.md). End users and browsers should **not** call the agent directly in production.

## Quick start

### Prerequisites

- Python **3.11+**
- An LLM provider (OpenAI, Anthropic, or local Ollama) configured for LiteLLM
- A CTIX v3 instance for full integration (optional for partial/local testing)

### Setup

```bash
cd ctix-attack-flow-agent
cp agent/.env.example agent/.env
# Edit agent/.env: CTIX_*, LLM keys, optional rate limits and TTP_CHAINER_PATH

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
ctix-attack-flow-agent/
├── webapp/                     # Standalone UI + API (v1 demo; BYOK for LLM)
├── agent/                      # FastAPI service
│   ├── app/
│   │   ├── main.py             # App factory, middleware, exception handlers
│   │   ├── config.py           # pydantic-settings
│   │   ├── api/                # Routes, middleware, schemas
│   │   ├── core/               # Pipeline, narrative, TLP, jobs, errors
│   │   ├── integrations/       # CTIX client, ttp_chainer adapter
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
| `CTIX_BASE_URL` | CTIX base URL | (required for integration) |
| `CTIX_ACCESS_ID` / `CTIX_SECRET_KEY` | HMAC for **inbound** agent API and CTIX client usage | (required in prod) |
| `CTIX_VERIFY_SSL` | Verify TLS to CTIX | `true` |
| `RATE_LIMIT_PER_TENANT` | Max `generate` calls per tenant per window | `20` |
| `RATE_LIMIT_WINDOW_SECONDS` | Window length in seconds | `3600` |
| `NARRATIVE_TOKEN_BUDGET` / `NARRATIVE_MIN_SDOS` | Narrative assembly limits | see `.env.example` |
| `TTP_CHAINER_PATH` | Filesystem path to ttp_chainer | `/app/ttp_chainer` |
| `AGENT_HOST` / `AGENT_PORT` / `AGENT_LOG_LEVEL` | Bind and logging | `0.0.0.0`, `8000`, `INFO` |

## Deployment

- **Development:** `docker compose` or local `uvicorn` as above.
- **Production:** See [infra/](infra/) for Terraform targeting AWS ECS Fargate; run the agent in the same trust zone as CTIX app servers, with no public ingress to the agent port.

## Documentation

- [docs/PROXY_INTEGRATION.md](docs/PROXY_INTEGRATION.md) — Django proxy contract for CTIX backend.
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) — Agent HTTP API.

## Publishing on GitHub

- Confirm **no** `.env`, `*.tfvars` with secrets, or real API keys are tracked (`git log -p -- '*.env'` before the first push).
- Keep **[`agent/.env.example`](agent/.env.example)** and **[`webapp/backend/.env.example`](webapp/backend/.env.example)** as the only env templates (empty keys, comments only).
- Tag a release (e.g. `v1.0.0`) when the webapp is the “v1” you want others to clone and run.

## License

Proprietary — Cyware Technologies.
