# CodeGuard AI — Deployment Guide

> Step-by-step instructions to get the backend online, from zero to production.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Step 1: Create Supabase Project (Database + Auth)](#step-1-create-supabase-project)
3. [Step 2: Create GitHub OAuth App](#step-2-create-github-oauth-app)
4. [Step 3: Configure Supabase Auth Provider](#step-3-configure-supabase-auth-provider)
5. [Step 4: Create Upstash Redis (Optional)](#step-4-create-upstash-redis)
6. [Step 5: Generate Secrets](#step-5-generate-secrets)
7. [Step 6: Configure Environment Variables](#step-6-configure-environment-variables)
8. [Step 7: Push Database Schema](#step-7-push-database-schema)
9. [Step 8: Run Backend Locally](#step-8-run-backend-locally)
10. [Step 9: Verify Everything Works](#step-9-verify-everything-works)
11. [Step 10: Deploy to Railway (Free Tier)](#step-10-deploy-to-railway)
12. [Alternative: Deploy to Render](#alternative-deploy-to-render)
13. [Post-Deployment Checklist](#post-deployment-checklist)
14. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

- **Node.js 18+** installed
- **Git** installed
- **npm** or **pnpm** package manager
- A web browser for account creation

**Estimated time:** 30-45 minutes

---

## Step 1: Create Supabase Project

Supabase provides the PostgreSQL database and authentication. **Free tier: 2 projects, 500 MB database, 50K monthly active users.**

### 1.1 Create Account
1. Go to [https://supabase.com](https://supabase.com)
2. Click **"Start your project"** → Sign up with GitHub
3. Authorize Supabase

### 1.2 Create Project
1. Click **"New Project"**
2. Fill in:
   - **Organization:** Create or select one
   - **Name:** `codeguard-ai`
   - **Database Password:** Generate a strong password → **SAVE THIS PASSWORD** (you'll need it)
   - **Region:** Choose closest to you (e.g., `us-east-1`)
3. Click **"Create new project"**
4. Wait ~2 minutes for the project to be provisioned

### 1.3 Get API Keys
1. Go to **Settings** (gear icon in left sidebar) → **API**
2. Copy these values:

```
SUPABASE_URL = https://[your-project-ref].supabase.co        ← "Project URL"
SUPABASE_ANON_KEY = eyJhbGciOi...                             ← "anon/public" key
SUPABASE_SERVICE_ROLE_KEY = eyJhbGciOi...                     ← "service_role" key (keep secret!)
```

### 1.4 Get Database Connection Strings
1. Go to **Settings** → **Database**
2. Scroll to **"Connection string"** section
3. Select **"URI"** tab
4. Copy two connection strings:

```
# Pooler connection (for Prisma — port 6543)
DATABASE_URL=postgresql://postgres.[your-project-ref]:[YOUR-DB-PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres?pgbouncer=true

# Direct connection (for migrations — port 5432)
DIRECT_URL=postgresql://postgres.[your-project-ref]:[YOUR-DB-PASSWORD]@aws-0-[region].pooler.supabase.com:5432/postgres
```

**Replace `[YOUR-DB-PASSWORD]` with the database password you set in step 1.2.**

---

## Step 2: Create GitHub OAuth App

This allows users to log in via GitHub.

1. Go to [https://github.com/settings/applications/new](https://github.com/settings/applications/new)
2. Fill in:
   - **Application name:** `CodeGuard AI`
   - **Homepage URL:** `http://localhost:3000` (update to production URL later)
   - **Authorization callback URL:** `https://[your-project-ref].supabase.co/auth/v1/callback`
     > **Important:** The callback URL points to Supabase, not your backend. Supabase handles the OAuth flow.
3. Click **"Register application"**
4. Copy:

```
GITHUB_CLIENT_ID = Ov23li...           ← "Client ID"
GITHUB_CLIENT_SECRET = abc123...        ← Click "Generate a new client secret"
```

**Save the client secret immediately — GitHub only shows it once.**

---

## Step 3: Configure Supabase Auth Provider

1. In Supabase dashboard, go to **Authentication** → **Providers**
2. Find **GitHub** and click to expand
3. Toggle **"GitHub enabled"** → ON
4. Enter:
   - **Client ID:** The `GITHUB_CLIENT_ID` from step 2
   - **Client Secret:** The `GITHUB_CLIENT_SECRET` from step 2
5. Click **"Save"**

---

## Step 4: Create Upstash Redis (Optional)

Upstash provides Redis for caching and rate limiting. **Free tier: 10K commands/day, 256 MB.** The backend works without Redis (rate limiting and caching are disabled).

1. Go to [https://upstash.com](https://upstash.com)
2. Sign up (GitHub login works)
3. Click **"Create Database"**
   - **Name:** `codeguard-ai`
   - **Region:** Same as your Supabase project
   - **Type:** Regional
4. Go to the **"REST API"** tab
5. Copy:

```
UPSTASH_REDIS_REST_URL = https://[your-redis].upstash.io
UPSTASH_REDIS_REST_TOKEN = AX...your-token
```

---

## Step 5: Generate Secrets

Generate a JWT secret for signing authentication tokens:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the output:
```
JWT_SECRET = a1b2c3d4...64-character-hex-string
```

---

## Step 6: Configure Environment Variables

### 6.1 Create the .env file
```bash
cd codeguard-ai
cp .env.example .env
```

### 6.2 Fill in your values
Open `.env` and replace the placeholders:

```env
# ─── Required ─────────────────────────────────────────────
SUPABASE_URL=https://[your-ref].supabase.co
SUPABASE_ANON_KEY=eyJhbGciOi...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...
DATABASE_URL=postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres
GITHUB_CLIENT_ID=Ov23li...
GITHUB_CLIENT_SECRET=abc123...
JWT_SECRET=your-64-char-hex-from-step-5

# ─── Optional ─────────────────────────────────────────────
UPSTASH_REDIS_REST_URL=https://[your-redis].upstash.io
UPSTASH_REDIS_REST_TOKEN=AX...

# ─── Server ───────────────────────────────────────────────
PORT=3000
NODE_ENV=development
API_BASE_URL=http://localhost:3000
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

---

## Step 7: Push Database Schema

This creates all tables in your Supabase PostgreSQL database.

```bash
cd backend
npm install
npx prisma generate
npx prisma db push
```

**Expected output:**
```
🚀  Your database is now in sync with your Prisma schema.
```

### Verify tables were created
1. Go to Supabase dashboard → **Table Editor**
2. You should see these tables:
   - `users`
   - `api_keys`
   - `teams`
   - `team_members`
   - `projects`
   - `scans`
   - `ghin_reports`
   - `ghin_packages`
   - `policy_templates`
   - `webhooks`
   - `webhook_deliveries`

### Optional: View schema in Prisma Studio
```bash
npx prisma studio
```
This opens a web UI at `http://localhost:5555` where you can browse and edit data.

---

## Step 8: Run Backend Locally

```bash
cd backend

# Development mode (hot-reload)
npm run dev
```

**Expected output:**
```
[INFO] Prisma client initialized
[INFO] Database connected
[INFO] GHIN consolidation daemon started
[INFO] CodeGuard AI Backend running on port 3000
[INFO] Routes registered: { health, api, auth, ghin, scans, teams, admin }
```

---

## Step 9: Verify Everything Works

### 9.1 Health Check
```bash
curl http://localhost:3000/health
```
Expected: `{"status":"ok","timestamp":"..."}`

### 9.2 Readiness Check (DB + Redis)
```bash
curl http://localhost:3000/health/ready
```
Expected: `{"status":"ready","database":"connected",...}`

### 9.3 API Info
```bash
curl http://localhost:3000/api
```
Expected: JSON with version `7.2.0`, all endpoints, and feature flags.

### 9.4 GHIN Stats
```bash
curl http://localhost:3000/api/ghin/stats
```
Expected: `{"totalPackages":0,"confirmedHallucinations":0,...}`

### 9.5 Test GitHub OAuth
Open in browser: `http://localhost:3000/api/auth/github`
This should redirect you to GitHub for authorization.

### 9.6 GHIN Package Check
```bash
curl http://localhost:3000/api/ghin/check/NPM/faker-colors-js
```
Expected: `{"packageName":"faker-colors-js","ecosystem":"NPM","known":false,...}`

---

## Step 10: Deploy to Railway (Free Tier)

Railway provides free hosting with $5/month credit. **Enough for a backend + database.**

### 10.1 Create Railway Account
1. Go to [https://railway.app](https://railway.app)
2. Sign up with GitHub

### 10.2 Install Railway CLI
```bash
npm install -g @railway/cli
railway login
```

### 10.3 Create Project
```bash
cd codeguard-ai/backend
railway init
```
- Choose **"Create new project"**
- Name it `codeguard-ai-backend`

### 10.4 Set Environment Variables
```bash
railway variables set SUPABASE_URL="https://[your-ref].supabase.co"
railway variables set SUPABASE_ANON_KEY="eyJhbGciOi..."
railway variables set SUPABASE_SERVICE_ROLE_KEY="eyJhbGciOi..."
railway variables set DATABASE_URL="postgresql://..."
railway variables set DIRECT_URL="postgresql://..."
railway variables set GITHUB_CLIENT_ID="Ov23li..."
railway variables set GITHUB_CLIENT_SECRET="abc123..."
railway variables set JWT_SECRET="your-hex-string"
railway variables set NODE_ENV="production"
railway variables set PORT="3000"
railway variables set API_BASE_URL="https://your-app.railway.app"
railway variables set CORS_ORIGINS="https://your-app.railway.app,http://localhost:5173"
```

If you have Upstash:
```bash
railway variables set UPSTASH_REDIS_REST_URL="https://..."
railway variables set UPSTASH_REDIS_REST_TOKEN="AX..."
```

### 10.5 Deploy
```bash
railway up
```

Railway will:
1. Detect it's a Node.js project
2. Run `npm install`
3. Run `npm run build`
4. Start with `npm start`

### 10.6 Get Your URL
```bash
railway domain
```
This generates a public URL like `https://codeguard-ai-backend-production.up.railway.app`

### 10.7 Update GitHub OAuth Callback
Go back to your GitHub OAuth app settings and update the callback URL:
```
https://[your-project-ref].supabase.co/auth/v1/callback
```
And update your API_BASE_URL Railway variable to match the new domain.

---

## Alternative: Deploy to Render

Render offers a free tier for web services. **Free: 750 hours/month, auto-sleep after 15 min idle.**

### Create `render.yaml`
This is already provided in the repo. Just:

1. Go to [https://render.com](https://render.com)
2. Sign up with GitHub
3. Click **"New" → "Web Service"**
4. Connect your GitHub repo
5. Settings:
   - **Root Directory:** `backend`
   - **Build Command:** `npm install && npx prisma generate && npm run build`
   - **Start Command:** `npm start`
   - **Environment:** Node
6. Add all environment variables from your `.env` file
7. Click **"Create Web Service"**

---

## Post-Deployment Checklist

After deployment, verify everything:

- [ ] `GET /health` returns `200 OK`
- [ ] `GET /health/ready` shows database connected
- [ ] `GET /api` shows version `7.2.0` and feature flags
- [ ] `GET /api/ghin/stats` returns statistics
- [ ] `GET /api/auth/github` redirects to GitHub OAuth
- [ ] Complete OAuth flow returns a JWT token
- [ ] Create an API key via `POST /api/auth/api-keys`
- [ ] Use API key to upload a scan via `POST /api/scans`
- [ ] Update `API_BASE_URL` and `CORS_ORIGINS` env vars to match production URL
- [ ] Update GitHub OAuth callback URL to production domain

### Update CLI to use your backend
After deployment, you can configure the CLI to upload scans:
```bash
# In your project's .codeguard/config.json
{
  "apiUrl": "https://your-app.railway.app",
  "apiKey": "cg_your_api_key_here"
}
```

### Update Extension settings
In VS Code settings:
```json
{
  "codeguard.ghinApiUrl": "https://your-app.railway.app"
}
```

---

## Troubleshooting

### "Missing required environment variable"
- Check that your `.env` file exists and has all required keys
- For Railway/Render, verify env vars are set in the dashboard

### "Database connection failed"
- Verify `DATABASE_URL` has the correct password (no brackets)
- Check that the Supabase project is active (not paused)
- Ensure the connection string uses port `6543` for pooler

### "Prisma db push failed"
- Make sure `DIRECT_URL` uses port `5432` (not the pooler port)
- Check your database password doesn't contain special characters that need URL-encoding

### "GitHub OAuth not working"
- Verify the callback URL in GitHub matches exactly: `https://[ref].supabase.co/auth/v1/callback`
- Check that GitHub provider is enabled in Supabase Authentication → Providers
- Ensure `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are correct

### "Rate limiting not working"
- This is expected if Upstash Redis is not configured
- The backend works fine without Redis — rate limiting and caching are gracefully disabled

### "CORS errors"
- Update `CORS_ORIGINS` to include your frontend URL
- Multiple origins are comma-separated: `https://app.example.com,http://localhost:5173`

### Railway-specific
- If build fails, check that `backend/package.json` has correct scripts
- Use `railway logs` to see server output
- Ensure the `Procfile` or start script is correct

### Render-specific
- Free tier services auto-sleep after 15 minutes of inactivity
- First request after sleep takes ~30 seconds (cold start)
- Use the Render dashboard to check deploy logs

---

## Architecture After Deployment

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  VS Code / CLI   │────▶│  Railway/Render   │────▶│    Supabase      │
│  (your machine)  │     │  (Express API)    │     │  (PostgreSQL)    │
│                  │     │  Port 3000        │     │  (Auth)          │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                │                        │
                                ▼                        │
                         ┌──────────────────┐            │
                         │  Upstash Redis   │            │
                         │  (cache + rate)  │            │
                         └──────────────────┘            │
                                                         │
                         ┌──────────────────┐            │
                         │  GitHub OAuth    │◀───────────┘
                         │  (login flow)    │
                         └──────────────────┘
```

**Total cost: $0/month** on free tiers of all services.

---

*Created for CodeGuard AI v7.2.0 — Last updated: March 2026*
