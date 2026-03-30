# Attack Flow Agent

**Turn threat intelligence into MITRE ATT&CK–aware attack flows** — STIX-friendly exports, interactive graphs (React Flow), and optional detection-rule generation. Ships as a **FastAPI agent service**, a **standalone browser app** (`webapp/`), and Terraform/CloudFormation examples for cloud deploys.

**You bring your own LLM API keys.** Nothing is hardcoded; never commit `.env` or put secrets in `VITE_*` frontend variables.

---

## Start here

| I want to… | Go to |
| --- | --- |
| **Try the app locally** (upload STIX/PDF, explore the graph, export, rules) | **[`webapp/README.md`](webapp/README.md)** — primary quick start |
| **Run or integrate the HTTP agent** (jobs, HMAC, upstream report fetch) | This file → [Quick start (agent)](#quick-start-agent) and **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)** |
| **Put a proxy in front of the agent** (browser → your backend → agent) | **[`docs/PROXY_INTEGRATION.md`](docs/PROXY_INTEGRATION.md)** |
| **Deploy on AWS** (Fargate, ALB, S3, CloudFront) | **[`webapp/AWS_DEPLOY.md`](webapp/AWS_DEPLOY.md)** and **[`webapp/infra/cloudformation/README.md`](webapp/infra/cloudformation/README.md)** |
| **Deploy frontend to Netlify** | **[`webapp/NETLIFY.md`](webapp/NETLIFY.md)** |

---

## Table of contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Quick start (standalone web app)](#quick-start-standalone-web-app)
- [Quick start (agent)](#quick-start-agent)
- [API summary](#api-summary)
- [Configuration](#configuration)
- [Documentation index](#documentation-index)
- [Security & secrets](#security--secrets)
- [Deployment notes](#deployment-notes)
- [License](#license)

---

## Features

- **Attack flow graph** — Techniques, tools, and relationships as an explorable flow (React Flow + Dagre layout in the webapp).
- **Inputs** — STIX 2.1 bundles, PDF reports (webapp), or report IDs via the agent API when integrated with an upstream platform.
- **Exports** — STIX bundle, MITRE AFB-oriented JSON, flow graph JSON, PNG; analyst-oriented rule packs where implemented.
- **Detection rules (webapp)** — LLM-assisted generation (Sigma, YARA, Suricata, and extended formats per UI); **backend-only** API keys.
- **Agent API** — Async jobs, tenant header, HMAC auth, rate limits, health with dependency hints.

---

## Repository layout

```text
attack-flow-agent/
├── webapp/                 ← Start here for the v1 demo (README inside)
│   ├── backend/            FastAPI + ttp_chainer adapter
│   ├── frontend/           Vite + React + MUI + React Flow
│   ├── AWS_DEPLOY.md       AWS options + CloudFormation pointer
│   └── infra/cloudformation/
├── agent/                  FastAPI microservice (integration-style API)
├── docs/                   PROXY_INTEGRATION.md, API_REFERENCE.md
├── frontend/               Embedded React feature module (scaffold)
├── infra/terraform/      ECS / ALB / ECR patterns
├── docker-compose.yml
└── README.md               ← You are here
```

---

## Quick start (standalone web app)

Full steps, env vars, and deploy options are in **[`webapp/README.md`](webapp/README.md)**.

```bash
# Backend (from repo root)
cd webapp/backend
cp .env.example .env
# Set OPENAI_API_KEY, TTP_CHAINER_PATH (see .env.example)
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Frontend (separate terminal)
cd webapp/frontend
npm install && npm run dev
# Open http://localhost:5173 — API proxied to :8000
```

---

## Quick start (agent)

For the **integration agent** (not the standalone webapp UI):

### Prerequisites

- Python **3.11+**
- LLM access via LiteLLM (see `agent/.env.example`)
- Optional: upstream threat-intel API credentials if you use the bundled HTTP client

### Setup

```bash
cd attack-flow-agent
cp agent/.env.example agent/.env
# Edit agent/.env: LLM keys, optional upstream URL/HMAC, TTP_CHAINER_PATH

cd agent
pip install -r requirements.txt
# or: pip install -e ".[dev]"

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Docker

```bash
docker compose up -d
docker compose logs -f agent
```

### Verify

```bash
curl -s http://localhost:8000/api/v1/health | jq .
```

Authenticated routes require `X-Tenant-Id` and HMAC query parameters — see **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)**.

---

## API summary

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/attack-flow/generate` | Queue generation for a report |
| `GET` | `/api/v1/attack-flow/jobs/{id}` | Job status and result |
| `GET` | `/api/v1/attack-flow/report/{id}` | Latest flow for a report |
| `GET` | `/api/v1/attack-flow/{flow_id}/export/{fmt}` | Export `stix`, `afb`, or `flowviz` |
| `GET` | `/api/v1/health` | Health (no auth) |

Details, errors, and schemas: **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)**.

---

## Configuration

Environment templates (no secrets committed):

| File | Purpose |
| --- | --- |
| [`agent/.env.example`](agent/.env.example) | Agent service, LLM, optional upstream API |
| [`webapp/backend/.env.example`](webapp/backend/.env.example) | Standalone web API + CORS + models |

Variable meanings are documented in comments inside each `*.env.example` file.

---

## Documentation index

| Document | Contents |
| --- | --- |
| **[`webapp/README.md`](webapp/README.md)** | Standalone app: local dev, Fly.io, Docker, Netlify pointer |
| **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)** | REST API, auth, errors |
| **[`docs/PROXY_INTEGRATION.md`](docs/PROXY_INTEGRATION.md)** | How to proxy the agent from your backend |
| **[`webapp/AWS_DEPLOY.md`](webapp/AWS_DEPLOY.md)** | AWS deployment patterns |
| **[`webapp/infra/cloudformation/README.md`](webapp/infra/cloudformation/README.md)** | Fargate + CloudFormation walkthrough |
| **[`webapp/NETLIFY.md`](webapp/NETLIFY.md)** | Static frontend + API redirect |
| **[`PRODUCT_STORY.md`](PRODUCT_STORY.md)** / **[`VISION_EXPANDED_PLATFORM.md`](VISION_EXPANDED_PLATFORM.md)** | Product context and roadmap-style notes |

---

## Security & secrets

- **Never commit** `.env`, real API keys, or `*.tfvars` with secrets.
- **Never use** `VITE_*` for LLM or upstream credentials (they ship to the browser).
- Prefer **Secrets Manager** / **host env** in production; see `webapp/AWS_DEPLOY.md`.
- Report security issues through your organization’s process (add `SECURITY.md` if you adopt a public disclosure policy).

---

## Deployment notes

- **Development:** `docker compose` or local `uvicorn` as above.
- **Production agent:** See [`infra/terraform/`](infra/terraform/) — run beside your app tier; no public agent port without a proxy.
- **Production webapp:** See [`webapp/AWS_DEPLOY.md`](webapp/AWS_DEPLOY.md) and CloudFormation README.

Releases are tagged (e.g. **`v1.0.0`**). Use **GitHub Releases** for changelog-style notes if you want discoverability for each tag.

---

## License

Proprietary — Cyware Technologies.
