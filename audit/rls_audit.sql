-- rls_audit.sql — multi-tenant Row-Level-Security readiness audit for Postgres / Supabase.
--
-- WHAT IT DOES: read-only. Inspects your live schema's RLS posture and emits one findings table.
-- It never writes, never changes a policy, never reads row DATA — only catalog metadata
-- (pg_class, pg_policies, pg_proc). Safe to run against production.
--
-- HOW TO RUN:
--   psql "$DATABASE_URL" -f rls_audit.sql                     # human-readable
--   psql "$DATABASE_URL" -t -A -F',' -f rls_audit.sql > findings.csv   # machine-readable for the report
--
-- The 7 checks below are the ones that actually leak tenant data in production multi-tenant SaaS,
-- in rough order of blast radius. Each finding has a severity and a one-line remediation.
--
-- SEVERITY: CRITICAL = a tenant can read/write another tenant's data today.
--           HIGH      = a likely isolation gap or a privilege-escalation surface.
--           MEDIUM    = a hardening gap (defense-in-depth) or a drift risk.
--           INFO      = posture metric, not a defect.

\set ON_ERROR_STOP on

-- A single UNION-ALL result set: (severity, check, object, detail, remediation).
WITH

-- CHECK 1 (CRITICAL): tables with RLS DISABLED. The Postgres default is rls=off, and most managed
-- Postgres (incl. Supabase) grants anon/authenticated full CRUD by default → an RLS-off table is
-- world-readable/writable to any authenticated (often any anon) JWT. This is the #1 real leak.
c1 AS (
  SELECT 'CRITICAL' sev, 'rls-disabled' chk,
         n.nspname||'.'||c.relname obj,
         'RLS is NOT enabled — any role with table grants bypasses tenant isolation' detail,
         'ALTER TABLE '||quote_ident(n.nspname)||'.'||quote_ident(c.relname)||' ENABLE ROW LEVEL SECURITY;' remediation
  FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND NOT c.relrowsecurity
    AND c.relname <> 'spatial_ref_sys'   -- PostGIS system table — documented exemption
),

-- CHECK 2 (CRITICAL): RLS enabled but ZERO policies. RLS-on + no-policy = deny-all for normal roles,
-- which SOUNDS safe — but table owners and BYPASSRLS roles still see everything, and teams routinely
-- "fix" the resulting empty reads by adding a permissive USING(true). A 0-policy RLS table is a
-- latent gap: it's either silently broken (app can't read) or about to be opened too wide.
c2 AS (
  SELECT 'CRITICAL' sev, 'rls-on-no-policy' chk,
         n.nspname||'.'||c.relname obj,
         'RLS enabled but no policies defined — deny-all for normal roles; a permissive policy is likely coming' detail,
         'Add a tenant-scoped policy: USING (tenant_id = <your tenant predicate>)' remediation
  FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
    AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname)
),

-- CHECK 3 (CRITICAL): permissive USING(true) policies — the classic "RLS theatre". The table has
-- RLS on AND a policy, so an audit checkbox passes, but the policy lets everyone through. Detect
-- USING that is literally `true` (whitespace-tolerant) and not scoped to anything.
c3 AS (
  SELECT 'CRITICAL' sev, 'using-true' chk,
         schemaname||'.'||tablename||' ['||policyname||']' obj,
         'Policy USING clause is unconditionally true — RLS is enabled but enforces nothing' detail,
         'Replace USING(true) with a tenant predicate, e.g. USING (tenant_id = <tenant fn>())' remediation
  FROM pg_policies
  WHERE schemaname = 'public'
    AND qual IS NOT NULL
    AND btrim(lower(qual)) IN ('true', '(true)')
),

-- CHECK 4 (HIGH): write policies with no WITH CHECK. A policy can let a row be READ correctly but,
-- lacking WITH CHECK, allow a user to INSERT/UPDATE a row INTO ANOTHER tenant (set tenant_id = X).
-- Read-isolation without write-isolation is a cross-tenant write hole.
c4 AS (
  SELECT 'HIGH' sev, 'no-with-check' chk,
         schemaname||'.'||tablename||' ['||policyname||']' obj,
         'Write-capable policy ('||cmd||') has no WITH CHECK — a user may write rows into another tenant' detail,
         'Add WITH CHECK (tenant_id = <tenant fn>()) to the policy' remediation
  FROM pg_policies
  WHERE schemaname = 'public'
    AND cmd IN ('ALL', 'INSERT', 'UPDATE')
    AND with_check IS NULL
),

-- CHECK 5 (HIGH): tables missing a tenant discriminator column entirely. If there's no tenant_id /
-- organization_id / account_id / company_id / workspace_id, the table cannot be tenant-scoped at all
-- (it's either global reference data — fine — or an un-scopable leak). Flag for a human to classify.
c5 AS (
  SELECT 'HIGH' sev, 'no-tenant-column' chk,
         n.nspname||'.'||c.relname obj,
         'No tenant discriminator column found (tenant_id/org_id/account_id/company_id/workspace_id) — cannot be tenant-scoped; confirm this is global reference data, not un-scoped tenant data' detail,
         'If tenant data: add a tenant_id column + RLS. If shared reference: enable RLS with a read-all + admin-write policy.' remediation
  FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'spatial_ref_sys'
    AND NOT EXISTS (
      SELECT 1 FROM pg_attribute a
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        AND a.attname IN ('tenant_id','organization_id','org_id','account_id','company_id','workspace_id')
    )
),

-- CHECK 6 (HIGH): SECURITY DEFINER functions without a locked search_path. A DEFINER function runs
-- with the owner's privileges; if its search_path is mutable, a caller can shadow a table/function
-- it references and escalate. A pinned search_path closes this.
c6 AS (
  SELECT 'HIGH' sev, 'definer-mutable-search-path' chk,
         n.nspname||'.'||p.proname obj,
         'SECURITY DEFINER function without a pinned search_path — privilege-escalation surface' detail,
         'ALTER FUNCTION '||quote_ident(n.nspname)||'.'||quote_ident(p.proname)||'(...) SET search_path = public, pg_temp;' remediation
  FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
  WHERE n.nspname = 'public' AND p.prosecdef
    AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) cfg WHERE cfg LIKE 'search_path=%')
),

-- CHECK 7 (MEDIUM): anon role with write grants on a public table. Even with RLS, an explicit
-- INSERT/UPDATE/DELETE grant to anon is a defense-in-depth smell (and a foot-gun if a permissive
-- policy ever lands). Belt-and-suspenders: revoke anon writes unless a public form genuinely needs it.
c7 AS (
  SELECT DISTINCT 'MEDIUM' sev, 'anon-write-grant' chk,
         table_schema||'.'||table_name obj,
         'anon role holds a '||privilege_type||' grant — revoke unless a public/anon flow needs it' detail,
         'REVOKE '||privilege_type||' ON '||quote_ident(table_schema)||'.'||quote_ident(table_name)||' FROM anon;' remediation
  FROM information_schema.role_table_grants
  WHERE table_schema = 'public' AND grantee = 'anon'
    AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')
),

-- INFO: posture metrics (the numerator/denominator a buyer wants on the cover page).
info AS (
  SELECT 'INFO' sev, 'posture' chk, 'public schema' obj,
    (SELECT count(*)::text FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relkind='r')
    ||' tables; '||
    (SELECT count(*)::text FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity)
    ||' RLS-enabled; '||
    (SELECT count(*)::text FROM pg_policies WHERE schemaname='public')||' policies' detail,
    'baseline metric' remediation
)

SELECT sev AS severity, chk AS check, obj AS object, detail, remediation
FROM (
  SELECT * FROM info
  UNION ALL SELECT * FROM c1
  UNION ALL SELECT * FROM c2
  UNION ALL SELECT * FROM c3
  UNION ALL SELECT * FROM c4
  UNION ALL SELECT * FROM c5
  UNION ALL SELECT * FROM c6
  UNION ALL SELECT * FROM c7
) findings
ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','INFO'], severity), check, object;
