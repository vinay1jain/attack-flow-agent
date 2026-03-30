# Deploy Attack Flow on AWS

This app is two parts:

| Part | What it is | Typical AWS home |
|------|------------|------------------|
| **Frontend** | Static Vite/React build (`npm run build` → `dist/`) | **S3** + **CloudFront** (or **Amplify Hosting**) |
| **Backend** | FastAPI on port 8000, long-ish LLM calls | **ECS Fargate** + **ALB**, or **App Runner**, or **EC2** |

The browser only talks to **`/api/*`** on the **same hostname** as the UI (recommended). **CloudFront** can route `/api/*` to your load balancer and everything else to S3—same pattern as Netlify redirects.

**Do not** put `OPENAI_API_KEY` in frontend env vars (`VITE_*`). Store it in **AWS Secrets Manager** or **SSM Parameter Store** and inject it into the container/task only.

---

## Prerequisites

- AWS account and IAM user/role with rights to create the resources below (or use **AdministratorAccess** for a first pass in a sandbox).
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) configured (`aws configure`).
- [Docker](https://docs.docker.com/get-docker/) (for container image).
- Local builds work: backend runs, `webapp/frontend` runs `npm run build`.

---

## Recommended architecture (production-style)

```
User → CloudFront (HTTPS)
         ├─ /api/*     → Application Load Balancer → ECS Fargate (FastAPI)
         └─ /*         → S3 (static index.html + assets)
```

Secrets: `OPENAI_API_KEY` in **Secrets Manager**, referenced from the ECS task definition.

**IaC for this path:** [`webapp/infra/cloudformation/attack-flow-stack.yaml`](infra/cloudformation/attack-flow-stack.yaml) — full CLI walkthrough in [`webapp/infra/cloudformation/README.md`](infra/cloudformation/README.md) (ECR push, secret ARN, deploy, `FrontendUrl` update, `s3 sync`, invalidation).

---

### Step 1 — Container image for the API

From your machine, in the **backend** folder (same context as the existing `Dockerfile`):

```bash
cd webapp/backend

# Local test (optional)
docker build -t attack-flow-api:local .
docker run --rm -p 8000:8000 -e OPENAI_API_KEY="sk-..." attack-flow-api:local
# curl http://localhost:8000/api/health
```

Create an **ECR** repository and push (replace `ACCOUNT_ID` and `REGION`):

```bash
export AWS_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws ecr create-repository --repository-name attack-flow-api --region $AWS_REGION 2>/dev/null || true

aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

docker tag attack-flow-api:local $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/attack-flow-api:v1
docker push $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/attack-flow-api:v1
```

---

### Step 2 — Secret for the API key

```bash
aws secretsmanager create-secret \
  --name attack-flow/openai-api-key \
  --secret-string '{"OPENAI_API_KEY":"sk-your-real-key"}' \
  --region $AWS_REGION
```

Or store **only** the raw key string if you prefer a simpler JSON key in the console. You will map this into the task as `OPENAI_API_KEY` (see ECS task definition docs for `secrets` → `valueFrom` ARN).

---

### Step 3 — VPC and load balancer

For a first deployment you can use the **default VPC** in your region.

1. **Create a security group** for the ALB: inbound **443** (and **80** if you redirect to HTTPS) from `0.0.0.0/0`.
2. **Create an ALB** (internet-facing), attach that SG, two subnets in the default VPC.
3. **Create a target group**: type **IP**, protocol **HTTP**, port **8000**, health check path **`/api/health`** (or `/docs` if you prefer).
4. **Listener**: HTTP 80 → forward to target group (add HTTPS + ACM certificate when you have a domain).

---

### Step 4 — ECS Fargate service

1. **Cluster**: ECS → Create cluster → **Networking only** (Fargate).
2. **Task definition**:
   - Launch type: **Fargate**.
   - CPU/memory: e.g. **1 vCPU / 2 GB** (increase if analyses time out).
   - Container: image = ECR URI from Step 1, port **8000**.
   - **Environment variables** (plain):
     - `FRONTEND_URL` = your **CloudFront URL** (e.g. `https://d111111abcdef8.cloudfront.net`) or custom domain—must match browser origin for CORS.
     - `LLM_MODEL` / `LLM_EXTRACTION_MODEL` if not defaults.
   - **Secrets** (from Secrets Manager): inject `OPENAI_API_KEY`.
3. **Service**: desired count **1** (or more), subnets = default VPC private/public as required, **security group** for tasks: allow **8000** **only from the ALB security group**.
4. Wait until the service is stable and targets are **healthy** on the target group.

Note the **ALB DNS name** (e.g. `attack-flow-alb-123.us-east-1.elb.amazonaws.com`). Test:

`curl http://<ALB_DNS>/api/health`

---

### Step 5 — S3 + CloudFront (frontend + `/api` proxy)

1. **S3 bucket** (e.g. `attack-flow-ui-YOURNAME`): Block Public Access **on**; you will serve via CloudFront only.
2. **Build and upload** the UI:

   ```bash
   cd webapp/frontend
   npm ci && npm run build
   aws s3 sync dist/ s3://attack-flow-ui-YOURNAME/ --delete
   ```

3. **CloudFront distribution**
   - **Origin 1 (default):** S3, use **Origin Access Control (OAC)** so the bucket stays private. Attach bucket policy allowing that OAC to `s3:GetObject`.
   - **Origin 2:** **Custom origin** = your **ALB DNS** (HTTP, port 80 or 443 as configured).  
   - **Behaviors:**
     - **Path pattern `Default (*)`** → S3 origin.  
       - Use a **custom error response**: HTTP **403** and **404** → **200** → `/index.html` (SPA fallback).
     - **Path pattern `/api/*`** → ALB origin.  
       - **Cache policy**: **CachingDisabled** (or minimal TTL).  
       - **Allowed methods**: include **GET, HEAD, OPTIONS, PUT, POST, DELETE** (upload/analyze need POST).

4. **CORS / Host header (important)**  
   - CloudFront forwards `Host` from the viewer by default; your ALB may need to accept that host or you use a **custom origin request policy** to set Host to the ALB hostname—if health checks fail from CloudFront, check ALB listener rules and origin settings.

5. When you have the **CloudFront domain** (e.g. `https://dxxxx.cloudfront.net`):

   - Set **`FRONTEND_URL`** on the ECS task to that exact URL (including `https://`) and **redeploy** the service so CORS allows the browser.

6. Open the CloudFront URL in a browser; run **Analyze** and confirm network tab shows `/api/analyze` **200** via the same domain.

---

### Step 6 — Custom domain (optional)

1. Request a certificate in **ACM** in **us-east-1** (required for CloudFront).
2. Add **alternate domain name (CNAME)** on the distribution, attach the ACM cert.
3. **Route 53** (or your DNS): `CNAME` or `ALIAS` for `app.example.com` → CloudFront distribution domain.

Use `https://app.example.com` as `FRONTEND_URL` in ECS.

---

## Simpler path: Amplify + App Runner

| Layer | Service | Notes |
|-------|---------|--------|
| UI | **AWS Amplify Hosting** | Connect Git repo or upload `dist/`; build command `npm run build`, output `dist`. |
| API | **App Runner** | “Container registry” → ECR image from Step 1; set env + secret for `OPENAI_API_KEY`; get a `*.awsapprunner.com` URL. |

**Caveat:** The UI is on an Amplify URL and the API on App Runner—**different origins**. You must either:

- Add **CloudFront** in front of both (advanced), or  
- Change the frontend to use a **`VITE_API_BASE_URL`** at build time pointing to the App Runner URL **and** ensure `FRONTEND_URL` on the API lists the Amplify URL for CORS (current backend already uses `FRONTEND_URL`).

That code change is not in the repo by default; the **CloudFront single-domain** approach avoids it.

---

## Minimal path: one EC2 instance

For demos or internal use:

1. **EC2** (Amazon Linux 2023), security group **22** (your IP) + **80** + **443**.
2. Install Docker; copy `webapp/` to the instance.
3. Build frontend on the instance or locally and `scp` `dist/`.
4. Run **nginx** + **docker** for API (same `docker-compose` pattern as `HOSTING.md` in the repo root), or run `uvicorn` under **systemd** behind nginx.

Use **Let’s Encrypt** for TLS on the EC2 public DNS or a small Route 53 record.

---

## Checklist before go-live

- [ ] `OPENAI_API_KEY` only in Secrets Manager / task env—never in Git or S3.
- [ ] `FRONTEND_URL` matches the **exact** URL users type (scheme + host, no trailing slash issues).
- [ ] CloudFront `/api/*` **not** cached for POST bodies (use CachingDisabled).
- [ ] ALB idle timeout ≥ longest analyze (default 60s may be low; consider **120–300s** for LLM).
- [ ] Fargate task CPU/memory enough for PDF + LLM spikes.
- [ ] **HTTPS** end-to-end for production (CloudFront + ALB HTTPS recommended).

---

## Cost (rough order of magnitude)

- **Fargate + ALB + NAT (if private subnets)**: tens to low hundreds USD/month depending on traffic and size.
- **S3 + CloudFront**: usually small at low traffic.
- **App Runner + Amplify**: often simpler billing, still pay for App Runner vCPU/memory and build minutes.

Use the [AWS Pricing Calculator](https://calculator.aws/) with your region and expected requests.

---

## Related files in this repo

- `webapp/backend/Dockerfile` — API image.
- `webapp/infra/cloudformation/attack-flow-stack.yaml` — Fargate + ALB + S3 + CloudFront (single stack).
- `webapp/infra/cloudformation/README.md` — deploy commands and troubleshooting for that template.
- `webapp/NETLIFY.md` — same **single-origin `/api` proxy** idea as CloudFront behaviors.
- `webapp/HOSTING.md` — generic docker-compose / nginx notes.

For **App Runner + Amplify** or **EC2**, use this doc’s manual steps; there is no second IaC template in-repo yet.
