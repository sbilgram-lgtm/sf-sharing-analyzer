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
| OWD Analysis | 4 |
| Role Hierarchy | 8 |
| Territory Management | 3 |
| Sharing Rules | 4 |
| Manual Sharing | 2 |
| Apex Sharing | 3 |
| Record Teams | 2 |
| Groups & Queues | 3 |
| Permission Bypasses | 6 |
| Implicit Sharing | 3 |
| External & Guest Access | 2 |
| **Total** | **40** |

## Key Findings This Tool Surfaces

- Objects with Public Read/Write internal or external OWD — including sensitive objects like Case, Opportunity, and Lead
- Users with View All Data or Modify All Data — detected via **both profile and permission set grants**
- Apex classes running without sharing enforcement — complete inventory with class names
- Sharing rules targeting All Internal Users — org-wide visibility grants that negate Private OWD
- Manual sharing volume per object — high counts signal a compensating control for a poorly designed sharing model
- Role hierarchy depth, breadth, and empty roles
- Territory 2.0 model health — empty territories, inactive rules, multiple active models
- Implicit sharing chains — Contact/Case controlled by Account parent
- External OWD exposure — objects accessible to guest and portal users

## Stack

- React 18 + TypeScript (Create React App)
- Express (Node 20) + jsforce v1
- jsPDF + jspdf-autotable (PDF export)
- xlsx (Excel export)
- Deployed on Railway

## Setup

### 1. Create a Connected App in Salesforce

In Setup → App Manager → New Connected App:

- **OAuth Scopes:** `api`, `refresh_token`, `offline_access`
- **Callback URL:** `https://sf-sharing-analyzer-production.up.railway.app/auth/callback` (or `http://localhost:3001/auth/callback` for local dev)
- **PKCE:** No additional configuration needed — supported automatically

### 2. Run Locally

```bash
npm install
npm run dev
```

Opens React on `http://localhost:3000`, Express on `http://localhost:3001`.

### 3. Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | Yes | Random string for session signing |
| `GEMINI_API_KEY` | No | Enables AI chat panel |
| `GROQ_API_KEY` | No | Alternative AI provider |

## What's New

### October 2026
- Initial release — 40 checks across 11 categories
- Permission bypass detection covers both profile and permission set grants
- Current State Inventory tab with full OWD table and sharing rule catalog
- Remediation Roadmap export with 4 phases prioritized by risk and effort

## Related

- [SF Tech Debt Assessor](https://github.com/sbilgram-lgtm/sf-tech-debt-assessor) — 402-check Salesforce org health assessment across 23 categories
