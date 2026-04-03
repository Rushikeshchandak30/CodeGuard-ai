# Entity-Relationship Diagram

## Text ERD

```
┌──────────────────────────────────────────────────────────────────┐
│                        CodeGuard AI Database                     │
└──────────────────────────────────────────────────────────────────┘

┌─────────┐      ┌────────────┐      ┌─────────┐      ┌──────────┐
│  users  │──┬──▶│  api_keys  │      │  teams  │──┬──▶│projects  │
└─────────┘  │   └────────────┘      └─────────┘  │   └──────────┘
  id PK       │                        id PK        │     id PK
  email       │   ┌────────────────┐   name         │     team_id FK
  name        │   │ team_members   │   slug         │     name
  role        ├──▶│ (join table)   │◀──┤            │     repo_url
              │   └────────────────┘   plan         │
              │     team_id FK         members[]     │
              │     user_id FK         projects[]    │
              │     role               policies[]    │
              │                                      │
              │   ┌─────────────┐                    │
              ├──▶│    scans    │◀───────────────────┘
              │   └─────────────┘
              │     id PK
              │     user_id FK
              │     project_id FK
              │     source (CLI/EXT/…)
              │     total_findings
              │     security_score
              │     findings_json
              │     sbom_json
              │
              │   ┌──────────────┐     ┌────────────────┐
              └──▶│ ghin_reports │     │ ghin_packages  │
                  └──────────────┘     └────────────────┘
                    id PK                id PK
                    user_id FK           package_name
                    package_name         ecosystem
                    ecosystem            report_count
                    report_type          status (SUSPECTED/
                    confidence           CONFIRMED/…)
                    verified             verified_at

┌───────────────────┐     ┌──────────────────────┐
│  policy_templates │     │       webhooks        │
└───────────────────┘     └──────────────────────┘
  id PK                     id PK
  team_id FK                 team_id FK
  name                       url
  is_public                  events[]
  policy_json                secret
                             deliveries[]
                                  │
                             ┌────┴─────────────────┐
                             │   webhook_deliveries  │
                             └───────────────────────┘
                               webhook_id FK
                               event
                               payload
                               status_code
                               success
```

## Relationship Summary

| Table | Relates To | Type | On Delete |
|-------|-----------|------|-----------|
| api_keys | users | Many-to-One | CASCADE |
| team_members | teams + users | Many-to-Many join | CASCADE |
| projects | teams | Many-to-One | CASCADE |
| scans | users | Many-to-One | CASCADE |
| scans | projects | Many-to-One | SET NULL |
| ghin_reports | users | Many-to-One | SET NULL |
| policy_templates | teams | Many-to-One | CASCADE |
| webhooks | teams | Many-to-One | CASCADE |
| webhook_deliveries | webhooks | Many-to-One | CASCADE |

## Notes
- `ghin_packages` is NOT directly related to `ghin_reports` via FK — it is rebuilt
  periodically by the consolidation daemon from the reports table.
- `scans` stores full JSON blobs (`findings_json`, `sbom_json`, `ai_sbom_json`)
  for efficient retrieval without joins.
- All IDs use CUID (collision-resistant unique identifiers), not sequential integers.
