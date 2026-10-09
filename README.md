# SF Sharing Analyzer

A free, read-only web app that connects to any Salesforce org via OAuth and runs a comprehensive sharing and visibility architecture review — covering every layer of the Salesforce sharing model from OWD through Apex managed sharing.

**Live App:** https://sf-sharing-analyzer-production.up.railway.app

## What It Does

Produces two outputs in a single assessment run:

- **Findings Dashboard** — Critical / High / Medium / Low findings with drill-down to affected users, objects, and rules
- **Current State Inventory** — Full OWD table, sharing rule counts by object, team feature status, permission bypass summary, territory model stats

## Assessment Categories

| Category | Checks |
|---|---|
| OWD Analysis | 5 |
| Role Hierarchy | 8 |
| Territory Management | 5 |
| Sharing Rules | 9 |
| Manual Sharing | 3 |
| Apex Sharing | 7 |
| Record Teams | 3 |
| Groups & Queues | 7 |
| Permission Bypasses | 11 |
| Implicit Sharing | 3 |
| External & Guest Access | 3 |
| **Total** | **64** |

## Key Findings This Tool Surfaces

- Objects with Public Read/Write internal or external OWD — including sensitive objects like Case, Opportunity, and Lead
- Child objects set to Controlled by Parent where the parent OWD is Private — implicit sharing dependency
- Users with View All Data or Modify All Data — detected via **both profile and permission set grants**
- Percentage of active users who bypass sharing entirely — flags orgs where sharing provides little real access control
- Apex classes running without sharing enforcement — complete inventory with class names
- Apex-managed share record volumes per object, and zombie sharing reasons with no active Apex class
- Sharing rules targeting All Internal Users — org-wide visibility grants that negate Private OWD
- Redundant sharing rules on objects where OWD is already Public Read/Write
- Manual sharing volume per object — compensating pattern detection (Private OWD + high manual shares)
- Role hierarchy depth, breadth, and empty roles
- Territory 2.0 model health — empty territories, users in 50+ territories, hard-coded IDs in rules
- Implicit sharing chains — Contact/Case controlled by Account parent
- External OWD exposure — objects accessible to guest and portal users, HVPU sharing sets
- Case teams active on a Private Case OWD — architectural dependency flag
- Queues on objects where OWD is already Public (ownership provides no access control)

## Stack

- React 18 + TypeScript (Create React App)
- Express (Node 20) + jsforce v1
- jsPDF + jspdf-autotable (PDF export)
- xlsx (Excel export)
- Deployed on Railway

## Setup

### Option A — External Client App (Spring '25+ Orgs)

In Setup → External Client Apps → New External Client App:

- **OAuth Scopes:** `api`, `refresh_token`, `offline_access`
- **Callback URL:** `https://sf-sharing-analyzer-production.up.railway.app/auth/callback`
- No wait time required after saving

### Option B — Connected App (All Orgs)

In Setup → App Manager → New Connected App:

- **OAuth Scopes:** `api`, `refresh_token`, `offline_access`
- **Callback URL:** `https://sf-sharing-analyzer-production.up.railway.app/auth/callback`
- Wait 2–10 minutes after saving before connecting

### Run Locally

```bash
npm install
npm run dev
```

Opens React on `http://localhost:3000`, Express on `http://localhost:3001`.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | Yes | Random string for session signing |
| `GEMINI_API_KEY` | No | Enables AI chat panel |
| `GROQ_API_KEY` | No | Alternative AI provider |

## What's New

### October 2026 (64 checks)
- Added 12 new checks from Salesforce Winter '27 Sharing & Visibility Best Practices:
  - **Apex Sharing:** Classes with no sharing declaration (defaults to without-sharing behavior)
  - **Sharing Rules:** Per-object proximity to 300-rule and 50 criteria-rule platform limits; restriction rules inventory
  - **Permission Bypasses:** No Permission Set Groups defined; Author Apex / Manage Users permission holders
  - **Groups & Queues:** Queues with DoesIncludeBosses on Private OWD objects; nested public groups

### October 2026 (52 checks)
- Added 13 checks to complete original scope: OWD chain confusion, territory users in 50+ territories, hard-coded territory rule IDs, redundant sharing rules on Public OWD objects, Private OWD + high manual shares compensating pattern, Apex share volume per object/reason, zombie Apex sharing reasons, case teams with Private Case OWD, queues on Public OWD objects, >5% bypass threshold, permission set vs profile bypass breakdown, HVPU sharing sets
- Login page "What's Covered" now expands per category to show individual check titles with severity indicators
- Added External Client App setup instructions for Spring '25+ orgs
- Added disclaimer footer

### October 2026 (initial release — 40 checks)
- Initial release across 11 categories
- Permission bypass detection covers both profile and permission set grants
- Current State Inventory tab with full OWD table and sharing rule catalog
- Remediation Roadmap export with 4 phases prioritized by risk and effort

## Related

- [SF Tech Debt Assessor](https://github.com/sbilgram-lgtm/sf-tech-debt-assessor) — 402-check Salesforce org health assessment across 23 categories
