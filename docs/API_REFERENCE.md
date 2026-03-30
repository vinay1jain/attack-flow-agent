# Attack Flow Agent — API Reference

**Base URL:** `http://<agent-host>:8000/api/v1`

Interactive schema: `GET /docs` (Swagger UI) and `GET /openapi.json` on the same host.

---

## Authentication

### HMAC query parameters

All endpoints **except** `/health` (and the documentation/OpenAPI routes) expect these query parameters on every request:

| Parameter | Description |
| --- | --- |
| `AccessID` | Service access identifier |
| `Expires` | Unix timestamp in **seconds** (typically current time + 30) |
| `Signature` | Base64 **HMAC-SHA1** of the UTF-8 string `{AccessID}\n{Expires}` using the shared secret |

Newline is a single `\n` between access id and expires. `Expires` must be **greater than or equal to** server time when the request is processed.

Configuration on the agent: `CTIX_ACCESS_ID`, `CTIX_SECRET_KEY`.

**Development note:** If `CTIX_ACCESS_ID` is unset or empty, the agent **does not** enforce HMAC (allows unauthenticated access). Do not deploy production without setting credentials.

### Tenant header

All endpoints **except** `/health` and documentation require:

| Header | Description |
| --- | --- |
| `X-Tenant-Id` | Non-empty tenant identifier (isolation, rate limits, CTIX callbacks) |

Optional:

| Header | Description |
| --- | --- |
| `X-User-Id` | Opaque user id string for logging and job metadata |

---

## POST /attack-flow/generate

Triggers asynchronous attack-flow generation for a CTIX report.

**Request body (JSON):**

```json
{
  "report_id": "report--abc-123",
  "force_regenerate": false
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `report_id` | string | Yes | CTIX report STIX id |
| `force_regenerate` | boolean | No (default `false`) | When `false`, an existing completed flow may be returned without starting a new pipeline run |

**Response `202 Accepted` (new job):**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Attack flow generation started"
}
```

**Response `202 Accepted` (cached flow):** If `force_regenerate` is `false` and a flow already exists for the report, the agent returns the **existing** job id and its **current** `status` (e.g. `completed`) with message:

`"Cached attack flow returned (use force_regenerate=true to rebuild)"`

**Common errors:**

| HTTP | Meaning |
| --- | --- |
| `400` | Missing or empty `X-Tenant-Id` |
| `401` | Missing/invalid/expired HMAC parameters |
| `422` | Report content insufficient (`AttackFlowError` body, see [Error format](#error-format)) |
| `429` | Per-tenant generation rate limit (middleware; often plain `detail` string) |

---

## GET /attack-flow/jobs/{job_id}

Returns the current state of a generation job.

**Response `200 OK`:**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "report_id": "report--abc-123",
  "tenant_id": "tenant-1",
  "status": "processing",
  "stage": "analyzing_techniques",
  "progress_message": "Analyzing techniques and building attack graph",
  "created_at": "2026-03-26T10:00:00+00:00",
  "started_at": "2026-03-26T10:00:01+00:00",
  "completed_at": null,
  "metadata": {
    "llm_model": null,
    "total_tokens": 0,
    "node_count": 0,
    "edge_count": 0,
    "error_code": null,
    "error_message": null
  },
  "result": null
}
```

- `created_at` / `started_at` / `completed_at` are ISO 8601 strings from the agent.
- When `status` is `completed`, `result` contains the full flow payload (including `flow_id`, `nodes`, `edges`, export payloads, etc.).
- When `status` is `failed`, inspect `metadata.error_code` / `metadata.error_message` when populated.

**Response `404`:** Unknown `job_id` — typically `{"detail": "Job <id> not found"}`.

### Job stages (pipeline order)

1. `fetching_report`
2. `checking_tlp`
3. `fetching_relations`
4. `assembling_narrative`
5. `analyzing_techniques`
6. `building_graph`
7. `converting_output`
8. `storing_results`
9. `complete`

### Job status values

| Value | Meaning |
| --- | --- |
| `queued` | Accepted, not yet running |
| `processing` | Pipeline executing |
| `completed` | Success; `result` populated |
| `failed` | Terminal error |

---

## GET /attack-flow/report/{report_id}

Returns the **latest completed** attack flow for the given report **in the current tenant** (derived from `X-Tenant-Id`).

**Response `200 OK`:** JSON object matching the stored `result` shape, including fields such as:

```json
{
  "flow_id": "flow-abc123",
  "report_id": "report--abc-123",
  "tenant_id": "tenant-1",
  "nodes": [],
  "edges": [],
  "generated_at": "2026-03-26T10:02:30+00:00",
  "llm_model": "openai/gpt-4o",
  "tlp_marking": "TLP:GREEN"
}
```

Exact keys depend on pipeline output (e.g. `stix_bundle`, `afb_data` may be present).

**Response `404`:** No completed flow for that report — `{"detail": "No attack flow found for report <id>"}`.

---

## GET /attack-flow/{flow_id}/export/{format}

Exports a completed flow. **`flow_id`** is the identifier inside the flow `result`, **not** the CTIX `report_id`.

Supported `format` values:

| Format | Content | Description |
| --- | --- | --- |
| `stix` | JSON object | STIX 2.1 bundle (`stix_bundle` from result) |
| `afb` | JSON object | MITRE Attack Flow Builder compatible payload |
| `flowviz` | JSON object | Wrapper with `nodes`, `edges`, and `metadata` for visualization tools |

Responses are JSON with `Content-Disposition` attachment filenames.

**Errors:**

| HTTP | Typical cause |
| --- | --- |
| `400` | Unsupported `format` |
| `404` | Unknown `flow_id`, or bundle slice missing for that format |

---

## GET /health

Liveness / dependency snapshot. **No authentication required.**

**Response `200 OK`:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "active_jobs": 2,
  "dependencies": {
    "ctix_api": "healthy",
    "llm_provider": "configured"
  }
}
```

- `status` is **`degraded`** when the agent cannot reach CTIX (`ctix_api`: `unreachable`).
- `llm_provider` is currently informational (`configured` when the process starts; not a live probe of the vendor API).

---

## Error format

### Structured application errors (`AttackFlowError`)

Many domain failures return:

```json
{
  "error_code": "REPORT_NOT_FOUND",
  "message": "The specified report was not found in CTIX.",
  "details": {}
}
```

| `error_code` | HTTP status | Description |
| --- | --- | --- |
| `REPORT_NOT_FOUND` | `404` | Report id not found in CTIX |
| `REPORT_CONTENT_INSUFFICIENT` | `422` | Not enough related objects / narrative to build a flow |
| `TLP_RESTRICTED` | `403` | TLP policy blocks external LLM; configure local model |
| `LLM_TIMEOUT` | `500` | LLM call exceeded timeout |
| `LLM_RATE_LIMITED` | `429` | Upstream LLM rate limit |
| `PIPELINE_VALIDATION_FAILED` | `500` | Post-generation validation failed |
| `INTERNAL_ERROR` | `500` | Unexpected failure (`details` may carry context) |
| `JOB_NOT_FOUND` | `404` | (Reserved; job 404s may use FastAPI `detail` instead) |
| `RATE_LIMITED` | `429` | Tenant generation cap (when raised as `AttackFlowError`) |
| `AUTH_FAILED` | `401` | Invalid HMAC |
| `TENANT_REQUIRED` | `400` | Missing tenant (middleware may use plain `detail` for missing header) |

`details` is an object with string values (e.g. interpolated template fields for messages).

### FastAPI `HTTPException` (plain)

Authentication middleware, tenant middleware, rate-limit middleware, and some 404 handlers return Starlette’s default shape:

```json
{
  "detail": "X-Tenant-Id header is required"
}
```

Integrations should handle both shapes.

---

## CORS

The agent enables permissive CORS by default (`allow_origins=["*"]`). In production behind Django only, tighten or strip public CORS at the edge as needed.
