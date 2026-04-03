# CodeGuard AI — Complete Setup Guide (0 → Production)
### From Zero to Fully Deployed in 30 Minutes

---

## 📋 What You'll Build

By the end of this guide, you'll have:

1. ✅ **VS Code Extension** installed in VS Code, Windsurf, and Cursor
2. ✅ **Backend API** running on Railway (or Render) with PostgreSQL database
3. ✅ **Frontend Dashboard** deployed and connected to your backend
4. ✅ **CLI Tool** installed globally for CI/CD pipelines
5. ✅ **GitHub Action** ready to scan PRs automatically

**Total Cost:** $0/month (all free tiers)

---

## 🎯 Phase 1: Create All Required Accounts (10 minutes)

### Required Accounts (Free Tier)

| Service | What It's For | Free Tier | Sign Up Link |
|---------|---------------|-----------|--------------|
| **Supabase** | PostgreSQL database + Auth | 2 projects, 500 MB, 50K users | https://supabase.com |
| **GitHub** | OAuth login + code hosting | Unlimited public repos | https://github.com |
| **Railway** or **Render** | Backend API hosting | 500 hrs/mo (Railway) or 750 hrs/mo (Render) | https://railway.app or https://render.com |

### Optional Accounts (Recommended)

| Service | What It's For | Free Tier | Sign Up Link |
|---------|---------------|-----------|--------------|
| **Upstash** | Redis (rate limiting + caching) | 10K commands/day, 256 MB | https://upstash.com |
| **Sentry** | Error monitoring | 5K events/month | https://sentry.io |
| **Resend** | Email notifications | 100 emails/day | https://resend.com |

---

## 🔑 Phase 2: Get Your API Keys (15 minutes)

### Step 2.1: Supabase Setup

1. Go to https://supabase.com → **New Project**
2. Project name: `codeguard-ai`
3. Database password: **Save this!** (e.g. `MySecurePass123!`)
4. Region: Choose closest to you
5. Click **Create new project** (takes ~2 minutes)

**Get your keys:**
- Go to **Settings** → **API**
  - Copy `Project URL` → This is your `SUPABASE_URL`
  - Copy `anon public` key → This is your `SUPABASE_ANON_KEY`
  - Copy `service_role` key (click "Reveal") → This is your `SUPABASE_SERVICE_ROLE_KEY`

- Go to **Settings** → **Database** → **Connection String** → **URI**
  - Copy the connection string
  - Replace `[YOUR-PASSWORD]` with your database password from step 3
  - This is your `DATABASE_URL` (use the one with `:6543` port for pooling)
  - Copy again and change `:6543` to `:5432` → This is your `DIRECT_URL`

**Example:**
```
SUPABASE_URL=https://abcdefghijk.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
DATABASE_URL=postgresql://postgres.abcdefghijk:MySecurePass123!@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.abcdefghijk:MySecurePass123!@aws-0-us-east-1.pooler.supabase.com:5432/postgres
```

---

### Step 2.2: GitHub OAuth App

1. Go to https://github.com/settings/applications/new
2. Fill in:
   - **Application name:** `CodeGuard AI`
   - **Homepage URL:** `http://localhost:3000` (change later for production)
   - **Authorization callback URL:** `http://localhost:3000/api/auth/callback/github`
3. Click **Register application**
4. Copy **Client ID** → This is your `GITHUB_CLIENT_ID`
5. Click **Generate a new client secret**
6. Copy the secret → This is your `GITHUB_CLIENT_SECRET`

**Example:**
```
GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
GITHUB_CLIENT_SECRET=1234567890abcdef1234567890abcdef12345678
```

---

### Step 2.3: Generate JWT Secret

Run this command in your terminal:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the output → This is your `JWT_SECRET`

**Example:**
```
JWT_SECRET=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

---

### Step 2.4: Upstash Redis (Optional but Recommended)

1. Go to https://upstash.com → **Create Database**
2. Name: `codeguard-redis`
3. Type: **Regional**
4. Region: Choose closest to you
5. Click **Create**
6. Go to **REST API** tab
7. Copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`

**Example:**
```
UPSTASH_REDIS_REST_URL=https://us1-merry-cat-12345.upstash.io
UPSTASH_REDIS_REST_TOKEN=AYQgASQgMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY=
```

---

### Step 2.5: Sentry (Optional)

1. Go to https://sentry.io → **Create Project**
2. Platform: **Node.js**
3. Project name: `codeguard-backend`
4. Copy the DSN from the setup page

**Example:**
```
SENTRY_DSN=https://abc123def456@o123456.ingest.sentry.io/7890123
```

---

### Step 2.6: Resend (Optional)

1. Go to https://resend.com → **API Keys**
2. Click **Create API Key**
3. Name: `CodeGuard Backend`
4. Copy the key

**Example:**
```
RESEND_API_KEY=re_abc123def456_xyz789
```

---

## 💻 Phase 3: Local Development Setup (5 minutes)

### Step 3.1: Clone & Install

```bash
# Navigate to your projects folder
cd c:\Users\rchandak\Downloads\codeguard-ai

# Install root dependencies (for VS Code extension)
npm install

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install

# Install CLI dependencies
cd ../cli
npm install
```

---

### Step 3.2: Configure Environment Variables

**Backend:**
```bash
cd backend
cp ../.env.example .env
```

Now open `backend/.env` and fill in ALL the keys you collected in Phase 2:

```env
# Supabase (from Step 2.1)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGci...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGci...
DATABASE_URL=postgresql://postgres.your-project:YOUR-PASSWORD@...6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.your-project:YOUR-PASSWORD@...5432/postgres

# Upstash Redis (from Step 2.4)
UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-token

# GitHub OAuth (from Step 2.2)
GITHUB_CLIENT_ID=Iv1.your-client-id
GITHUB_CLIENT_SECRET=your-client-secret

# Sentry (from Step 2.5)
SENTRY_DSN=https://your-dsn@sentry.io/project

# Resend (from Step 2.6)
RESEND_API_KEY=re_your-key

# JWT Secret (from Step 2.3)
JWT_SECRET=your-64-char-hex-string

# Server config
PORT=3000
NODE_ENV=development
API_BASE_URL=http://localhost:3000
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Rate limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100

# OSV.dev (no key needed)
OSV_API_URL=https://api.osv.dev
```

**Frontend:**
```bash
cd ../frontend
cp .env.example .env.local
```

Edit `frontend/.env.local`:
```env
VITE_API_URL=http://localhost:3000
```

---

### Step 3.3: Initialize Database

```bash
cd backend

# Generate Prisma client
npm run db:generate

# Push schema to Supabase (creates all 11 tables)
npm run db:push

# Seed initial data (admin user, known hallucinations, demo team)
npx tsx ../database/seeds/seed.ts
```

**Expected output:**
```
✅ Seeded admin user: admin@codeguard.ai
✅ Seeded 18 known hallucinated packages
✅ Seeded demo team: codeguard-team
✅ Seeded default policy template
```

---

### Step 3.4: Start Backend Locally

```bash
cd backend
npm run dev
```

**Expected output:**
```
🚀 CodeGuard AI Backend v7.2.0
📡 Server running on http://localhost:3000
✅ Database connected
✅ Redis connected (or ⚠️ Redis disabled if not configured)
🔐 Auth: GitHub OAuth + API Keys + JWT
```

**Test it:** Open http://localhost:3000/health in your browser
```json
{
  "status": "ok",
  "version": "7.2.0",
  "timestamp": "2026-04-02T07:30:00.000Z"
}
```

---

### Step 3.5: Start Frontend Locally

Open a **new terminal**:

```bash
cd frontend
npm run dev
```

**Expected output:**
```
VITE v5.4.0  ready in 500 ms

➜  Local:   http://localhost:5173/
➜  Network: use --host to expose
```

**Test it:** Open http://localhost:5173 in your browser → You should see the login page

---

## 🔨 Phase 4: Build & Install the Extension (5 minutes)

### Step 4.1: Install VSCE (one-time)

```bash
npm install -g @vscode/vsce
```

---

### Step 4.2: Build the Extension

```bash
# Go back to root
cd c:\Users\rchandak\Downloads\codeguard-ai

# Compile TypeScript
npm run compile

# Package as .vsix
vsce package
```

**Output:** `codeguard-ai-7.0.0.vsix` (or similar)

---

### Step 4.3: Install in VS Code

**Option 1 — Drag & Drop:**
1. Open VS Code
2. Drag `codeguard-ai-7.0.0.vsix` into the VS Code window

**Option 2 — Command:**
```bash
code --install-extension codeguard-ai-7.0.0.vsix
```

---

### Step 4.4: Install in Windsurf

**Method 1 — UI:**
1. Open Windsurf
2. Extensions panel (`Ctrl+Shift+X`)
3. Click `...` menu → **Install from VSIX...**
4. Select `codeguard-ai-7.0.0.vsix`

**Method 2 — Command:**
```bash
windsurf --install-extension codeguard-ai-7.0.0.vsix
```

---

### Step 4.5: Install in Cursor

```bash
cursor --install-extension codeguard-ai-7.0.0.vsix
```

Or use the same UI method as Windsurf.

---

### Step 4.6: Verify Extension Works

1. Open any JavaScript file in VS Code/Windsurf/Cursor
2. Add this line:
   ```javascript
   import { faker } from 'faker-colors-js';
   ```
3. You should see a **red squiggle** with the message:
   > ⚠️ Hallucinated package detected: faker-colors-js (NPM)

4. Open Command Palette (`Ctrl+Shift+P`) and run:
   - `CodeGuard AI: Open Dashboard`
   - `CodeGuard AI: Scan Current File`
   - `CodeGuard AI: Scan MCP Servers`

---

## 🚀 Phase 5: Deploy to Production (10 minutes)

### Option A: Deploy Backend to Railway

1. Go to https://railway.app → **New Project** → **Deploy from GitHub repo**
2. Connect your GitHub account and select the `codeguard-ai` repo
3. Railway will auto-detect the backend
4. Click **Add variables** and paste ALL your `.env` variables from Phase 3.2
5. **Important:** Update these for production:
   ```env
   NODE_ENV=production
   API_BASE_URL=https://your-app.up.railway.app
   CORS_ORIGINS=https://your-app.up.railway.app,https://your-frontend.vercel.app
   ```
6. Update GitHub OAuth callback URL:
   - Go to https://github.com/settings/developers
   - Edit your OAuth app
   - Change callback URL to: `https://your-app.up.railway.app/api/auth/callback/github`
7. Click **Deploy**

**Get your URL:** Railway will give you a URL like `https://codeguard-backend-production.up.railway.app`

---

### Option B: Deploy Backend to Render

1. Go to https://render.com → **New** → **Web Service**
2. Connect GitHub → Select `codeguard-ai` repo
3. Settings:
   - **Name:** `codeguard-backend`
   - **Root Directory:** `backend`
   - **Build Command:** `npm install && npm run build && npx prisma generate`
   - **Start Command:** `npm start`
4. Add all environment variables from Phase 3.2 (same as Railway)
5. Click **Create Web Service**

---

### Deploy Frontend to Vercel/Netlify

**Vercel:**
```bash
cd frontend
npm install -g vercel
vercel
```

Follow prompts, then update `frontend/.env.local`:
```env
VITE_API_URL=https://your-backend.up.railway.app
```

Redeploy:
```bash
vercel --prod
```

---

## 🧪 Phase 6: Verify Everything Works

### Backend Health Check

```bash
curl https://your-backend.up.railway.app/health
```

Expected:
```json
{
  "status": "ok",
  "version": "7.2.0"
}
```

---

### GHIN Stats Check

```bash
curl https://your-backend.up.railway.app/api/ghin/stats
```

Expected:
```json
{
  "totalPackages": 18,
  "confirmedHallucinations": 18,
  "totalReports": 0,
  "ecosystems": [...]
}
```

---

### Frontend Login

1. Open your frontend URL (e.g. `https://your-app.vercel.app`)
2. Click **Continue with GitHub**
3. Authorize the app
4. You should see the dashboard with stats

---

### Extension → Backend Connection

1. In VS Code/Windsurf, open Settings (`Ctrl+,`)
2. Search for `codeguard`
3. Set **CodeGuard AI: GHIN API URL** to your production backend:
   ```
   https://your-backend.up.railway.app
   ```
4. Scan a file → findings will now sync to the cloud

---

## 📦 Phase 7: Install CLI Globally

```bash
cd cli
npm install -g .
```

**Test:**
```bash
codeguard --version
# Output: 1.0.0

codeguard scan .
# Scans current directory
```

---

## 🔄 Phase 8: Add GitHub Action to Your Repos

Create `.github/workflows/codeguard.yml` in any repo:

```yaml
name: CodeGuard AI Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run CodeGuard AI
        uses: ./cli/action.yml
        with:
          fail-on-severity: high
          upload-sarif: true
        env:
          CODEGUARD_API_KEY: ${{ secrets.CODEGUARD_API_KEY }}
```

**Get your API key:**
1. Go to your frontend dashboard → **Settings**
2. Create a new API key: `GitHub Actions`
3. Copy the key (starts with `cg_`)
4. Add to GitHub repo secrets: `CODEGUARD_API_KEY`

---

## ✅ Final Checklist

- [ ] Extension installed in VS Code/Windsurf/Cursor
- [ ] Backend deployed to Railway/Render
- [ ] Frontend deployed to Vercel/Netlify
- [ ] Database seeded with initial data
- [ ] GitHub OAuth working (can log in to dashboard)
- [ ] Extension connected to backend (GHIN API URL set)
- [ ] CLI installed globally
- [ ] GitHub Action added to repos

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| `DATABASE_URL` connection fails | Check password has no special chars that need URL encoding. Use `encodeURIComponent()` if needed. |
| GitHub OAuth redirect fails | Verify callback URL matches exactly in GitHub app settings and `.env` |
| Extension not showing squiggles | Open a `.js`, `.ts`, `.py`, or `.json` file (not `.txt`) |
| `vsce: command not found` | Run `npm install -g @vscode/vsce` |
| Backend crashes on startup | Check all required env vars are set. Run `npm run db:push` to ensure schema is up to date. |
| Frontend can't reach backend | Check CORS_ORIGINS includes your frontend URL. Check API_BASE_URL is correct. |
| Rate limit errors | Upstash Redis not configured. Either add it or set high limits in `.env` |

---

## 📚 Next Steps

- Read `DEPLOYMENT_GUIDE.md` for advanced deployment options
- Read `PROJECT_SUMMARY.md` to understand what you built
- Read `EXTENSION_BUILD.md` for extension development workflow
- Check `database/` folder for schema docs and migration guides
- Explore the dashboard at your frontend URL

---

**🎉 Congratulations! You now have a fully production-ready AI-aware security platform.**

**Questions?** Open an issue on GitHub or check the docs in the repo.
