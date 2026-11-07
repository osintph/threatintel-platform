# Projects — Scoped Monitoring & Tracking

The Projects feature lets you create discrete monitoring engagements, each with their own keywords, target domains, entities, and hit tracking. Admins see all projects; regular users see only their own.

## Creating a Project

1. Navigate to the **📁 Projects** tab
2. Click **+ New Project**
3. Fill in:
   - **Name** — required, e.g. "ACME Corp Monitoring"
   - **Description** — optional context
   - **Color** — card accent color for visual identification
   - **Tags** — comma separated, e.g. `client, ransomware, brand`
   - **Alert Threshold** — minimum hits before an alert fires (default: 1)
   - **Status** — Active / Paused / Archived
4. Click **Save Project**

## Project Detail — Sub-tabs

Once a project is created, open it to configure what to monitor:

### Keywords
Project-specific keywords on top of global keyword config. Each keyword can be:
- **Plain text** — substring match against crawled content
- **Regex** — a regular expression (enable the Regex checkbox), run case-insensitively against the 1,000 characters around each keyword hit. It is checked when it is saved: a pattern that can backtrack catastrophically (`(a+)+`, `(a|aa)+`, back-references, repeats inside look-arounds) or is longer than 200 characters is refused with `The pattern is not accepted: <reason>`. The crawl checks stored patterns again; one saved before 1.3.0 that fails is skipped, with a warning naming the project and the pattern in the log of the process that ran the crawl (`docker compose logs dashboard` for a crawl started from the dashboard, `scanner` for `make scan`)
- **Category** — label for grouping (e.g. `credential`, `brand`, `person`)

### Domains
Target `.onion` addresses or clearnet domains to prioritise or track. Each domain has:
- **Priority** (1–5) — higher priority domains get added to the front of the crawl queue
- **Notes** — context about why this domain is being monitored

### Entities
Specific things to watch for in crawled content:
- **Person** — individual names
- **Organization** — company or group names
- **Brand** — product or brand names
- **IP Address** — specific IPs
- **Email** — email addresses
- **Bitcoin Address** — cryptocurrency addresses

### Hits
All keyword hits from the global crawl that matched this project's keywords, domains, or entities. Shows what triggered the match (keyword / domain / entity) and the matched value.

## How Matching Works

After every page is crawled and a keyword hit is recorded, the platform automatically checks all active projects:

1. **Keyword match** — a plain project keyword is contained in the hit's keyword, or a regex project keyword matches the hit's context (clipped to 1,000 characters)
2. **Domain match** — hit's source URL contains a project target domain
3. **Entity match** — hit's context snippet contains a project entity value

A hit can only be matched to a project once (no duplicates).

## Access Control

| Action | Admin | Project Owner | Other User |
|--------|-------|---------------|------------|
| View project | ✓ | ✓ | ✗ |
| Edit project | ✓ | ✓ | ✗ |
| Delete project | ✓ | ✓ | ✗ |
| View all projects | ✓ | ✗ | ✗ |

## API Endpoints

All endpoints require authentication.

```
GET    /api/projects                              List projects (admin: all, user: own)
POST   /api/projects                              Create project
GET    /api/projects/<id>                         Get project with full detail
PUT    /api/projects/<id>                         Update project
DELETE /api/projects/<id>                         Delete project
PATCH  /api/projects/<id>/status                  Change status

GET    /api/projects/<id>/keywords                List keywords
POST   /api/projects/<id>/keywords                Add keyword
DELETE /api/projects/<id>/keywords/<kid>          Remove keyword

GET    /api/projects/<id>/domains                 List domains
POST   /api/projects/<id>/domains                 Add domain
DELETE /api/projects/<id>/domains/<did>           Remove domain

GET    /api/projects/<id>/entities                List entities
POST   /api/projects/<id>/entities                Add entity
DELETE /api/projects/<id>/entities/<eid>          Remove entity

GET    /api/projects/<id>/hits                    Get matched hits
GET    /api/projects/<id>/stats                   Get hit statistics
```
