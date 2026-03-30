# Backend proxy integration specification

This document is the integration contract for the **host application** team (e.g. Django). It describes how to implement a thin, authenticated proxy in front of the Attack Flow Agent so browser and mobile clients never talk to the agent directly.

## Overview

The Attack Flow Agent is a standalone FastAPI microservice. Your backend should expose a **thin proxy layer** that:

1. Routes attack-flow requests to the agent over the internal network.
2. Validates user authentication using your existing HMAC (or session) patterns.
3. Enforces RBAC: only principals with **read** access to the underlying report may trigger generation, poll jobs, read flows, or export.
4. **Never** exposes the agent’s host, port, or credentials to the public internet.
5. Forwards required tenant and user context and signs outbound calls to the agent with **service** HMAC credentials.

The agent itself also validates HMAC on every request (except documentation and health). The values your backend uses to sign requests to the agent **must match** the agent’s HMAC credentials (see `agent/.env.example` and [Configuration](#configuration)).

## Endpoint mapping

| Your public path (example) | Method | Agent endpoint | Description |
| --- | --- | --- | --- |
| `/api/attack-flow/generate` | `POST` | `/api/v1/attack-flow/generate` | Trigger flow generation |
| `/api/attack-flow/jobs/{id}` | `GET` | `/api/v1/attack-flow/jobs/{id}` | Poll job status |
| `/api/attack-flow/report/{id}` | `GET` | `/api/v1/attack-flow/report/{id}` | Get latest flow for a report |
| `/api/attack-flow/{id}/export/{format}` | `GET` | `/api/v1/attack-flow/{id}/export/{format}` | Export flow (`stix`, `afb`, `flowviz`) |

Path parameters:

- `{id}` in **jobs** is the agent **job UUID**.
- `{id}` in **report** is the **report STIX ID** (e.g. `report--...`).
- `{id}` in **export** is the agent **flow_id** (string returned inside the completed flow payload), not the report id.

## Request flow

```text
User Browser → Your backend (e.g. Django) → Attack Flow Agent (FastAPI)
                    ↓
             1. Validate user auth (HMAC / session)
             2. Resolve report_id and enforce RBAC (read on report)
             3. Set X-Tenant-Id and X-User-Id from the authenticated context
             4. Append agent HMAC query params (AccessID, Expires, Signature)
             5. Forward method, body, and relevant path segments
             6. Return agent status code and JSON body to the client
```

**Timeouts:** Use conservative HTTP client timeouts (e.g. 30–60s for `generate` acknowledgment—the agent returns `202` quickly; long work happens asynchronously). For `GET` job/flow/export, shorter timeouts are usually sufficient unless your network is high-latency.

**Idempotency / caching:** If the client calls `POST .../generate` with `force_regenerate: false` and a completed flow already exists for that report, the agent may return `202` with the **existing** `job_id` and current `status` (e.g. `completed`) and a message indicating a cached result. The proxy should forward this transparently.

## Headers and query parameters

### Inbound from browser (your responsibility)

Define whatever JSON contract your product needs for `generate` (must match [API_REFERENCE.md](./API_REFERENCE.md): `report_id`, optional `force_regenerate`). Authenticate the user before proxying.

### Outbound to the agent (proxy MUST set)

| Name | Where | Description |
| --- | --- | --- |
| `X-Tenant-Id` | Header | Tenant identifier for isolation and rate limiting. Required on all agent routes except health/docs. |
| `X-User-Id` | Header | Optional but **recommended** for audit trails (string form of internal user id). |
| `AccessID` | Query | Service access id shared with the agent. |
| `Expires` | Query | Unix timestamp (seconds), typically **now + 30 seconds**. |
| `Signature` | Query | Base64-encoded HMAC-SHA1 of `{AccessID}\n{Expires}` using the shared secret. |

Signature algorithm (must match the agent implementation):

```text
message = f"{access_id}\n{expires}"  # expires as decimal string, same as query param
signature = base64.b64encode(
    hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha1).digest()
).decode("ascii")
```

Forward the **client request body** for `POST /generate` as JSON. For `GET` routes, forward query strings only if you add product-specific params; the agent does not require extra query params beyond HMAC.

## RBAC requirements

| Operation | Report scope | Rule |
| --- | --- | --- |
| **Generate** | Body `report_id` | User must have **read** (or your product’s equivalent) on that report. |
| **Job status** | Job is tied to `report_id` in agent state | User must have **read** on that report. Resolve `job_id` → `report_id` via your metadata store or by calling the agent only after you have already authorized the report (e.g. same session that started the job). |
| **View flow by report** | Path `report_id` | User must have **read** on that report. |
| **Export** | Flow belongs to a report | User must have **read** on the source report. Prefer enforcing this by only exposing `flow_id` values you previously served to an authorized user, or by mapping `flow_id` → `report_id` and checking read. |

The agent enforces tenant boundaries via `X-Tenant-Id`; it does **not** perform end-user RBAC—that remains entirely in your backend.

## Rate limiting

The agent enforces **per-tenant** limits on `POST /api/v1/attack-flow/generate` (default: **20** requests per **3600** seconds, configurable via `RATE_LIMIT_PER_TENANT` and `RATE_LIMIT_WINDOW_SECONDS`). You may add stricter **per-user** limits in your app server.

## Django implementation sketch

The following is illustrative—not a drop-in module. Adapt to your ASGI stack, decorators, and HTTP client.

```python
# attack_flow_proxy.py
import base64
import hashlib
import hmac
import time
from typing import Any

import httpx
from django.conf import settings
from django.http import JsonResponse
from django.views import View

# Example placeholders — replace with your real auth decorators / helpers.
# @require_hmac_auth
# @require_report_read("report_id")


def _agent_hmac_params() -> dict[str, str]:
    access_id = settings.ATTACK_FLOW_AGENT_ACCESS_ID
    secret = settings.ATTACK_FLOW_AGENT_SECRET_KEY.encode("utf-8")
    expires = str(int(time.time()) + 30)
    msg = f"{access_id}\n{expires}".encode("utf-8")
    sig = base64.b64encode(hmac.new(secret, msg, hashlib.sha1).digest()).decode("ascii")
    return {"AccessID": access_id, "Expires": expires, "Signature": sig}


def _agent_headers(request) -> dict[str, str]:
    return {
        "X-Tenant-Id": request.tenant_id,  # from your auth context
        "X-User-Id": str(request.user.pk),
    }


class GenerateAttackFlowView(View):
    async def post(self, request, *args, **kwargs):
        body: dict[str, Any] = ...  # parse JSON body from request
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                f"{settings.ATTACK_FLOW_AGENT_URL}/api/v1/attack-flow/generate",
                json=body,
                headers=_agent_headers(request),
                params=_agent_hmac_params(),
            )
        return JsonResponse(r.json(), status=r.status_code, safe=False)
```

Use the same `_agent_hmac_params()` and header builder for all proxied routes; only URL path and HTTP method change.

## Configuration

### Host application (Django) settings

```python
ATTACK_FLOW_AGENT_URL = env("ATTACK_FLOW_AGENT_URL", default="http://attack-flow-agent:8000")
ATTACK_FLOW_AGENT_ACCESS_ID = env("ATTACK_FLOW_AGENT_ACCESS_ID")
ATTACK_FLOW_AGENT_SECRET_KEY = env("ATTACK_FLOW_AGENT_SECRET_KEY")
```

### Agent service (must align)

On the agent, HMAC is validated against the access id and secret variables in **`agent/.env.example`**. In production, set these to the **same** access id and secret your backend uses when calling the agent (whether you name them `ATTACK_FLOW_AGENT_*` in Django or reuse a shared service principal is an operational choice; the bytes must match).

**Security:** If the agent’s access id env value is empty, the current build **skips** HMAC validation (intended for local dev only). Production deployments must set non-empty credentials.

## WebSocket integration (progress UX)

The agent does not expose a public WebSocket for job progress; clients poll `GET .../jobs/{job_id}` or use your own real-time channel. Recommended pattern:

1. After a successful `POST .../generate`, the frontend opens your existing WebSocket (or SSE) channel.
2. Your backend periodically polls the agent’s `GET /api/v1/attack-flow/jobs/{job_id}` (every 2–3 seconds is reasonable) using the same HMAC + headers.
3. Map agent fields (`status`, `stage`, `progress_message`) into product events and push to the client.
4. Stop polling when `status` is `completed` or `failed`, or after a maximum wait with a timeout message.

Suggested event envelope for your frontend:

`type`: `attack_flow.progress`

```json
{
  "type": "attack_flow.progress",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "stage": "analyzing_techniques",
  "message": "Analyzing techniques and building attack graph"
}
```

Map `message` from the agent’s `progress_message` field when present.

## Operational checklist

- [ ] Agent reachable only from VPC / private subnets (security groups, no public listener).
- [ ] Backend → agent TLS where applicable (or trusted overlay network).
- [ ] HMAC secrets rotated with agent config updated in lockstep.
- [ ] `X-Tenant-Id` always set and consistent with your tenant model.
- [ ] RBAC enforced on every proxied route.
- [ ] Logs correlate `X-User-Id`, `X-Tenant-Id`, `report_id`, and `job_id` for audits.

## References

- [API_REFERENCE.md](./API_REFERENCE.md) — request/response schemas and error codes.
- Agent OpenAPI: `http://<agent-host>:8000/docs` (disable or protect in production if desired).
