# Fargate + CloudFront — deploy with CloudFormation

Template: **`attack-flow-stack.yaml`**

## What it creates

- **S3** bucket for the static UI (private; CloudFront OAC only)
- **CloudFront** — default → S3, `/api/*` → **ALB** (no cache; origin request policy strips viewer `Host` so the ALB sees its own hostname)
- **ALB** + **ECS Fargate** service (1 task by default), **CloudWatch Logs**
- **IAM** roles for task execution + reading your OpenAI secret

## Before `aws cloudformation deploy`

### 1. VPC & subnets

Use your **default VPC** or any VPC with **public subnets** (and routes to an Internet Gateway).

```bash
export AWS_REGION=us-east-1
aws ec2 describe-subnets --filters "Name=default-for-az,Values=true" --query "Subnets[*].SubnetId" --output text
# Or pick two subnet IDs in different AZs from the console.
```

### 2. ECR image

From `webapp/backend`:

```bash
docker build -t attack-flow-api:v1 .
aws ecr create-repository --repository-name attack-flow-api --region $AWS_REGION 2>/dev/null || true
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
docker tag attack-flow-api:v1 $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/attack-flow-api:v1
docker push $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/attack-flow-api:v1
export IMAGE_URI=$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/attack-flow-api:v1
```

### 3. Secrets Manager (plain string = API key)

```bash
SECRET_ARN=$(aws secretsmanager create-secret \
  --name attack-flow-openai-key \
  --secret-string 'sk-YOUR-KEY' \
  --query ARN --output text)
echo $SECRET_ARN
```

Use the full **ARN** (including the random suffix) as `OpenAIApiKeySecretArn`.

### 4. Deploy the stack

```bash
cd webapp/infra/cloudformation

aws cloudformation deploy \
  --stack-name attack-flow-prod \
  --template-file attack-flow-stack.yaml \
  --capabilities CAPABILITY_IAM \
  --region $AWS_REGION \
  --parameter-overrides \
    VpcId=vpc-xxxxxxxx \
    PublicSubnetIds=subnet-aaa,subnet-bbb \
    ContainerImage=$IMAGE_URI \
    OpenAIApiKeySecretArn=$SECRET_ARN \
    FrontendUrl=https://placeholder.local
```

### 5. Point CORS at CloudFront

After the stack finishes, read outputs:

```bash
aws cloudformation describe-stacks --stack-name attack-flow-prod \
  --query "Stacks[0].Outputs" --output table
```

Copy **`CloudFrontURL`** (e.g. `https://d1111abcdef8.cloudfront.net`), then **update** the stack:

```bash
aws cloudformation deploy \
  --stack-name attack-flow-prod \
  --template-file attack-flow-stack.yaml \
  --capabilities CAPABILITY_IAM \
  --region $AWS_REGION \
  --parameter-overrides \
    VpcId=vpc-xxxxxxxx \
    PublicSubnetIds=subnet-aaa,subnet-bbb \
    ContainerImage=$IMAGE_URI \
    OpenAIApiKeySecretArn=$SECRET_ARN \
    FrontendUrl=https://d1111abcdef8.cloudfront.net
```

(Use your real CloudFront URL.) ECS will roll out a new task with the correct `FRONTEND_URL`.

> The backend also allows `*` in CORS for development; tightening that is recommended for production.

### 6. Upload the frontend

```bash
cd ../../frontend
npm ci && npm run build

BUCKET=$(aws cloudformation describe-stacks --stack-name attack-flow-prod \
  --query "Stacks[0].Outputs[?OutputKey=='UIBucketName'].OutputValue" --output text)

aws s3 sync dist/ "s3://$BUCKET/" --delete

DIST_ID=$(aws cloudformation describe-stacks --stack-name attack-flow-prod \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDistributionId'].OutputValue" --output text)

aws cloudfront create-invalidation --distribution-id "$DIST_ID" --paths "/*"
```

Open **`CloudFrontURL`** in a browser and run an analysis.

## Troubleshooting

| Symptom | Check |
|--------|--------|
| 502/504 on `/api/*` | Target group healthy? ECS task running? Security groups (ALB → task :8000). ALB idle timeout (template: 300s). |
| 403 from S3 | `UIBucketPolicy` must exist after distribution; re-run deploy if needed. |
| CORS errors | `FrontendUrl` parameter exactly matches `https://` + CloudFront domain (no trailing slash). |
| Task stops | CloudWatch Logs `/ecs/<stack>-api`; secret ARN and execution role `GetSecretValue`. |

## Costs

You pay for ALB, Fargate tasks, CloudFront data transfer, S3, and logs. Tear down when done:

```bash
aws cloudformation delete-stack --stack-name attack-flow-prod
```

Empty the S3 bucket first if delete fails (bucket not empty).

## See also

`webapp/AWS_DEPLOY.md` — broader AWS options and checklist.
