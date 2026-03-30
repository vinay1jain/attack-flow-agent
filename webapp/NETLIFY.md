# Deploy the frontend on Netlify

The UI is a static Vite build. API calls use **`/api`**, which Netlify rewrites to your **separately hosted** FastAPI backend (see `frontend/netlify.toml`).

## 1. Deploy the API elsewhere first

Examples: Fly.io, Railway, Render, a VM with `uvicorn`, or Docker. The API must be reachable over **HTTPS**.

Set on the backend (e.g. `webapp/backend/.env`):

- `FRONTEND_URL=https://<your-site>.netlify.app` (your exact Netlify URL, or custom domain)

This satisfies FastAPI CORS for browser requests.

## 2. Point Netlify at the backend

Edit **`webapp/frontend/netlify.toml`**:

Replace **`REPLACE-WITH-YOUR-API.example.com`** in `netlify.toml` with your API **host only** (no path):

```toml
to = "https://your-api-host.fly.dev/api/:splat"
```

Do **not** add a trailing slash on the host. The `:splat` passes through the path after `/api/`.

## 3. Netlify site settings

- **Base directory:** `webapp/frontend` (if the repo root is the monorepo / `attack-flow-agent`)
- **Build command:** `npm run build` (already in `netlify.toml`)
- **Publish directory:** `webapp/frontend/dist` (or `dist` if base directory is `webapp/frontend`)

If the Git repo root is **`webapp`** only, set base directory to **`frontend`**.

## 4. Environment variables (Netlify UI)

No secrets are required in the **frontend** build for the default setup. Optional:

- Add any future `VITE_*` vars here if you change the client to use them.

## 5. Verify

- Open `https://<your-site>.netlify.app`
- Upload or analyze; confirm network tab shows `/api/...` → 200 (rewritten to your API).

## Troubleshooting

| Issue | Check |
|--------|--------|
| CORS errors | `FRONTEND_URL` on API matches Netlify URL exactly |
| 404 on `/api` | Backend URL in `netlify.toml` wrong; API must expose `/api/health` |
| Blank page after deploy | Base directory / publish dir; run `npm run build` locally and confirm `dist/index.html` exists |
