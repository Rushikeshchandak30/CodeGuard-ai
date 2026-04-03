# Migration Guide

## Development Workflow

### First-time setup (no migration history)
```bash
cd backend
npx prisma db push          # Push schema directly — fast for dev
npx prisma generate          # Regenerate Prisma client
```

### Adding a new field or table
1. Edit `backend/prisma/schema.prisma`
2. Run:
```bash
npx prisma migrate dev --name describe_what_you_changed
# e.g. --name add_scan_labels
```
3. Commit the generated `prisma/migrations/` files

### Production deployment
```bash
npx prisma migrate deploy    # Applies all pending migrations safely
```

## Migration History

| # | Name | Date | Description |
|---|------|------|-------------|
| 001 | `init` | 2026-03-21 | Initial schema: users, api_keys, teams, projects, scans, ghin, policies, webhooks |
| 002 | `add_mcp_issues` | 2026-03-21 | Added `mcp_issues` count column to scans |

## Rules
- **Never edit** a migration file after it has been applied
- **Always** run `npx prisma generate` after any schema change
- Use `--name` flag describing the change in snake_case
- For destructive changes (drop column), create migration manually and test on staging first

## Rolling Back
Prisma does not support automatic rollbacks. To roll back:
1. Create a new migration that reverses the change
2. Apply it with `npx prisma migrate deploy`
