# CodeGuard AI — Database Layer

This folder contains everything related to the PostgreSQL database:
schema documentation, seed data, migration history, and SQL references.

## Structure

```
database/
├── README.md               ← You are here
├── schema/
│   ├── schema.prisma       ← Canonical schema (symlink to backend/prisma/schema.prisma)
│   └── SCHEMA_DOCS.md      ← Human-readable table reference
├── seeds/
│   ├── seed.ts             ← TypeScript seed script (run with npx ts-node)
│   └── ghin-seed.sql       ← SQL seed for known hallucinations (raw SQL fallback)
├── migrations/
│   └── MIGRATION_GUIDE.md  ← How to run migrations safely
└── diagrams/
    └── ERD.md              ← Entity-Relationship Diagram (text-based)
```

## Quick Commands

```bash
# From the backend/ directory:

# Generate Prisma client
npx prisma generate

# Push schema to database (dev — no migration files)
npx prisma db push

# Create a named migration (production — keeps history)
npx prisma migrate dev --name add_new_feature

# Apply pending migrations in production
npx prisma migrate deploy

# Open Prisma Studio (visual DB browser)
npx prisma studio

# Seed the database
npx ts-node database/seeds/seed.ts

# Reset DB (DANGER: drops all data)
npx prisma migrate reset
```

## Database Provider

- **Engine:** PostgreSQL 15 (hosted on Supabase)
- **ORM:** Prisma 5.22
- **Pooling:** PgBouncer via Supabase connection pooler (port 6543)
- **Direct connection:** port 5432 (for migrations only)
