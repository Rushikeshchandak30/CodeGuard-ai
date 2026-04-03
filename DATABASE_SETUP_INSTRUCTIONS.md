# 🗄️ Database Setup Instructions

## Quick Setup (2 minutes)

Your Supabase project is ready, but we need to create the tables manually.

### Step 1: Open Supabase SQL Editor

Click this link: https://supabase.com/dashboard/project/iwjierrgvqwpzphrfwan/sql/new

### Step 2: Copy & Paste This SQL

Open the file: `database/setup-supabase.sql`

Or copy this entire block:

```sql
-- Copy the entire contents of database/setup-supabase.sql here
```

### Step 3: Click "Run"

The SQL will:
- ✅ Create 11 tables (users, api_keys, teams, scans, ghin_packages, etc.)
- ✅ Create all indexes for performance
- ✅ Seed admin user (admin@codeguard.ai)
- ✅ Seed 18 known hallucinated packages
- ✅ Create default security policy

### Step 4: Verify Success

You should see: `Database setup complete! 🎉`

---

## Alternative: Enable Direct Connection

If you want to use `npm run db:push` instead:

1. Go to: https://supabase.com/dashboard/project/iwjierrgvqwpzphrfwan/settings/database
2. Scroll to **"Connection Pooling"**
3. Enable **"Allow connections from any IP address"** (for development)
4. Or add your IP address to the allowlist

Then run:
```bash
cd backend
npm run db:push
npx tsx ../database/seeds/seed.ts
```

---

## After Database Setup

Once tables are created, start the services:

```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev
```

Then open:
- Backend API: http://localhost:3000/health
- Frontend Dashboard: http://localhost:5173
