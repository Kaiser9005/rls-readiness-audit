# Multi-Tenant RLS Readiness Audit — productized deliverable

A fixed-fee, read-only audit of a Postgres / Supabase multi-tenant isolation posture. This folder is
the **delivery kit**: the sales landing page, the audit engine, and the report generator. Priced
against the $1,500–5,000 security-consultant anchor as a focused **$500 audit / $1,500 audit+fix**.

## The three pieces

| File | Role |
|---|---|
| `index.html` | the **landing / sales page** — outcome-framed, honest about what a finding is, priced vs the consultant anchor. CTA routes to GitHub (DM / issues) — no email exposed; add a booking email later. Host on GitHub Pages / Netlify / anywhere static. |
| `audit/rls_audit.sql` | the **audit engine** — read-only, runs against the buyer's live DB, emits findings. Inspects catalog metadata only; never touches row data or policies. |
| `report/generate_report.py` | the **report generator** — turns the audit's CSV output into a client-grade HTML report (→ Print-to-PDF, or `--pdf` with weasyprint/wkhtmltopdf). |

## Delivering an audit, end to end

```bash
# 1) Run the read-only audit against the client's DB (you, or them on a screen-share):
psql "$DATABASE_URL" -t -A -F',' -f audit/rls_audit.sql > findings.csv

# 2) Generate the branded report:
python3 report/generate_report.py findings.csv --client "Client Name" --out client-rls-audit.html

# 3) Open client-rls-audit.html → Print → Save as PDF  (or: --pdf if weasyprint/wkhtmltopdf installed)
#    Send the PDF. For the $1,500 tier, write the remediation migrations + re-run to prove closure.
```

The audit script is **safe to hand to the client to run themselves** — it's read-only and reads no
data. That's a selling point: a security-conscious buyer doesn't have to give you DB credentials.

## The 7 checks (and why each one is the leak)

1. **RLS disabled** (CRITICAL) — Postgres defaults RLS off; managed Postgres grants broad access → an RLS-off table is open to any role with grants.
2. **RLS on, no policy** (CRITICAL) — deny-all for normal roles, but a latent gap teams "fix" with a too-wide policy.
3. **`USING(true)`** (CRITICAL) — RLS theatre: enabled, has a policy, enforces nothing.
4. **Write policy, no `WITH CHECK`** (HIGH) — read-isolated but a user can write rows *into* another tenant.
5. **No tenant column** (HIGH) — can't be tenant-scoped; confirm it's global reference, not un-scoped tenant data.
6. **SECURITY DEFINER + mutable `search_path`** (HIGH) — privilege-escalation surface.
7. **anon write grants** (MEDIUM) — defense-in-depth foot-gun.

## Honesty (the differentiator)

A finding flags a **pattern worth a human's eyes**, not a guaranteed bug. A deliberate `USING(true)`
on shared reference data, or a no-`WITH CHECK` on a read-only `ALL` policy, are intentional — the
report says so. The deliverable's value is the **triaged shortlist + exact remediation SQL + the
judgment to tell a real leak from an intentional one**, plus a re-runnable script for CI. That candor
is what separates this from a scanner that dumps 200 false positives.

## Dogfooded

This audit script is the one run against a production multi-tenant ERP (447 tables, 446 RLS-enabled,
846 policies). Numbers trace to `../../PROOF-ARTIFACTS.md`. The pattern in miniature:
[fastapi-supabase-multitenant-starter](https://github.com/Kaiser9005/fastapi-supabase-multitenant-starter).

## To publish as a public lead-magnet (optional, you decide)

The `audit/rls_audit.sql` is genuinely useful standalone and would make a strong OSS lead-magnet
(drives the landing page). The `index.html` + `report/` are the paid-service wrapper. Suggested split
if you publish: open-source the audit SQL, keep the polished report generator as the service value-add.
