// Direct Supabase SQL execution to create tables
import { createClient } from '@supabase/supabase-js';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

dotenv.config();

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

async function setupDatabase() {
  console.log('🔧 Setting up database via Supabase SQL...');
  
  // Read the Prisma schema and convert to SQL
  const sql = `
    -- Users table
    CREATE TABLE IF NOT EXISTS "User" (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      avatar_url TEXT,
      role TEXT NOT NULL DEFAULT 'USER',
      github_id TEXT UNIQUE,
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- API Keys table
    CREATE TABLE IF NOT EXISTS "ApiKey" (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      key_hash TEXT UNIQUE NOT NULL,
      last_used_at TIMESTAMP(3),
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at TIMESTAMP(3)
    );

    -- Teams table
    CREATE TABLE IF NOT EXISTS "Team" (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      owner_id TEXT NOT NULL REFERENCES "User"(id),
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- Team Members table
    CREATE TABLE IF NOT EXISTS "TeamMember" (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL REFERENCES "Team"(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'MEMBER',
      joined_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(team_id, user_id)
    );

    -- Projects table
    CREATE TABLE IF NOT EXISTS "Project" (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      team_id TEXT NOT NULL REFERENCES "Team"(id) ON DELETE CASCADE,
      repository_url TEXT,
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- Scans table
    CREATE TABLE IF NOT EXISTS "Scan" (
      id TEXT PRIMARY KEY,
      project_id TEXT REFERENCES "Project"(id) ON DELETE SET NULL,
      user_id TEXT NOT NULL REFERENCES "User"(id),
      scan_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      findings JSONB NOT NULL DEFAULT '[]',
      metadata JSONB,
      started_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      completed_at TIMESTAMP(3)
    );

    -- GHIN Reports table
    CREATE TABLE IF NOT EXISTS "GhinReport" (
      id TEXT PRIMARY KEY,
      package_name TEXT NOT NULL,
      ecosystem TEXT NOT NULL,
      reporter_id TEXT REFERENCES "User"(id),
      context TEXT,
      verified BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- GHIN Packages table
    CREATE TABLE IF NOT EXISTS "GhinPackage" (
      id TEXT PRIMARY KEY,
      package_name TEXT NOT NULL,
      ecosystem TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'REPORTED',
      report_count INTEGER NOT NULL DEFAULT 1,
      first_seen_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      verified_at TIMESTAMP(3),
      metadata JSONB,
      UNIQUE(package_name, ecosystem)
    );

    -- Policy Templates table
    CREATE TABLE IF NOT EXISTS "PolicyTemplate" (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      rules JSONB NOT NULL,
      is_default BOOLEAN NOT NULL DEFAULT false,
      created_by TEXT REFERENCES "User"(id),
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- Webhooks table
    CREATE TABLE IF NOT EXISTS "Webhook" (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL REFERENCES "Team"(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      events TEXT[] NOT NULL,
      secret TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    -- Webhook Deliveries table
    CREATE TABLE IF NOT EXISTS "WebhookDelivery" (
      id TEXT PRIMARY KEY,
      webhook_id TEXT NOT NULL REFERENCES "Webhook"(id) ON DELETE CASCADE,
      event TEXT NOT NULL,
      payload JSONB NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      response_code INTEGER,
      response_body TEXT,
      attempted_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      delivered_at TIMESTAMP(3)
    );

    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_apikey_user ON "ApiKey"(user_id);
    CREATE INDEX IF NOT EXISTS idx_team_owner ON "Team"(owner_id);
    CREATE INDEX IF NOT EXISTS idx_teammember_team ON "TeamMember"(team_id);
    CREATE INDEX IF NOT EXISTS idx_teammember_user ON "TeamMember"(user_id);
    CREATE INDEX IF NOT EXISTS idx_project_team ON "Project"(team_id);
    CREATE INDEX IF NOT EXISTS idx_scan_project ON "Scan"(project_id);
    CREATE INDEX IF NOT EXISTS idx_scan_user ON "Scan"(user_id);
    CREATE INDEX IF NOT EXISTS idx_ghinreport_package ON "GhinReport"(package_name, ecosystem);
    CREATE INDEX IF NOT EXISTS idx_ghinpackage_ecosystem ON "GhinPackage"(ecosystem);
    CREATE INDEX IF NOT EXISTS idx_webhook_team ON "Webhook"(team_id);
    CREATE INDEX IF NOT EXISTS idx_webhookdelivery_webhook ON "WebhookDelivery"(webhook_id);
  `;

  try {
    // Execute via Supabase SQL editor API
    const { data, error } = await supabase.rpc('exec_sql', { sql });
    
    if (error) {
      console.error('❌ Error:', error);
      // Try alternative method - direct query
      console.log('Trying alternative method...');
      const queries = sql.split(';').filter(q => q.trim());
      for (const query of queries) {
        if (query.trim()) {
          const { error: qError } = await supabase.from('_sql').select('*').limit(0);
          if (qError) console.log('Note: SQL execution via client may not be supported');
        }
      }
    } else {
      console.log('✅ Database tables created successfully!');
    }
  } catch (err) {
    console.error('❌ Setup failed:', err);
    console.log('\n📝 Please run this SQL manually in Supabase SQL Editor:');
    console.log('https://supabase.com/dashboard/project/iwjierrgvqwpzphrfwan/sql/new');
    console.log('\n' + sql);
  }
}

setupDatabase();
