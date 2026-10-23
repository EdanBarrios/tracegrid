# Rules

Every finding has a **tier**:

- **Fix**: high confidence. Reachable by anon/authenticated (or PUBLIC) with no recognised
  caller and no dynamic call or dynamic SQL that could change that; client-read tables without
  RLS; owner-rights views over RLS tables; client-callable auth hooks. Act on these.
- **Review**: the same kinds of problem with a caveat (unresolved dynamic calls could reach it,
  dynamic SQL may grant or revoke, the service-role client was recognised by a heuristic, it is
  reached only indirectly), or a functional problem rather than an exposure (missing RPCs,
  tables the client cannot reach, uncalled edge functions, edge-function hints).
- **Info**: intended or benign patterns, such as helpers that RLS policies need.

The tier is not part of the fingerprint, so a finding that moves between tiers keeps its
baseline entry. Accepted findings (`tracegrid: ignore` hatches and `ignore` config) are not
findings at all; they are listed under Suppressed.

| Rule | Level | Meaning |
|---|---|---|
| `exposed-uncalled-function` | error | `anon`/`authenticated` can execute it and nothing references it. **Warning** when it is SECURITY INVOKER and authenticated-only, or when unresolved dynamic `.rpc()` calls could reach it (the note names them) |
| `granted-helper-function` | note | executable by those roles, no `.rpc()` caller, used by a policy, view, trigger, cron job or other SQL. **Warning** when it is SECURITY DEFINER and callable by anon, or no caller needs the grant |
| `client-table-without-rls` | error | client code reads a table with RLS off that anon/authenticated can reach |
| `client-view-without-security-invoker` | error | client code reads an owner-rights view (or materialized view) over RLS tables: RLS is bypassed |
| `client-table-without-policies` | warning | RLS on, but no permissive policy for anon/authenticated/PUBLIC: the client gets nothing |
| `client-table-not-granted` | warning | client code queries a table neither anon nor authenticated has privileges on (the 2026 "new tables are not exposed" default) |
| `auth-hook-function-exposed` | warning | a `[auth.hook.*]` Postgres function the client can execute |
| `missing-rpc` | error | code calls an RPC the schema does not define |
| `unknown-table` | warning | code queries a table or view the schema does not define |
| `uncalled-edge-function` | warning | no `functions.invoke`, `/functions/v1/<name>` URL, cron, webhook, auth hook or SQL caller, and not declared an entry point |
| `missing-edge-function` | error | invoked, but no such function in `supabase/functions` |
| `edge-service-role-before-auth` | warning | an edge function's first service_role / secret-key data use comes before every gate tracegrid recognises (heuristic; review, never fix; info for head/count-only endpoints) |
| `edge-request-controlled-fetch` | warning | an edge function calls `fetch()` with a URL taken from the request body (review) |

Tiers by rule: `exposed-uncalled-function`, `client-table-without-rls`,
`client-view-without-security-invoker` and `auth-hook-function-exposed` are Fix unless a caveat
applies (then Review); `granted-helper-function` is Info, or Review when it is SECURITY DEFINER
and callable by anon or not needed by any caller. Functions named in a `DO` block that creates or
alters policies with `EXECUTE` count as policy-used and are never Fix. The rest are Review.
Plugin rules may set `tier`; otherwise error maps to Fix, warning to Review, note to Info.

Functions are identified as `name/arity` (`next_invoice_number/1`). Each finding has a stable
fingerprint, `<rule>:<subject>`, records whether it rests on migrations or the live catalog,
and may carry a `note` or `confidence: low`.

## Rules at a glance

Tier, and an example of what trips each rule (demo app and typical projects).

| Rule | Tier | Example |
|---|---|---|
| `exposed-uncalled-function` | Fix (Review with a caveat) | `internal_cleanup()` is executable by `anon` and nothing calls it |
| `granted-helper-function` | Info (Review when SECURITY DEFINER and anon-callable) | `is_member(uuid)` used only inside an RLS policy but granted to `authenticated` |
| `client-table-without-rls` | Fix | `supabase.from('audit_log')` with RLS off |
| `client-view-without-security-invoker` | Fix | client reads a view without `security_invoker = true` over RLS tables |
| `client-table-without-policies` | Review | RLS enabled, no permissive policy: the client gets zero rows |
| `client-table-not-granted` | Review | a new table the client queries but never `GRANT`ed to `authenticated` |
| `auth-hook-function-exposed` | Fix | `[auth.hook.custom_access_token]` function executable by `authenticated` |
| `missing-rpc` | Review | `.rpc('get_totals')` with no such function in migrations |
| `unknown-table` | Review | `.from('legacy_view')` not defined in the schema |
| `uncalled-edge-function` | Review | `supabase/functions/old-sync` with no invoker |
| `missing-edge-function` | Review | `functions.invoke('send-sms')` with no function directory |
| `edge-service-role-before-auth` | Review | service-role query runs before the request is authenticated |
| `edge-request-controlled-fetch` | Review | `fetch(body.url)` inside an edge function |

[Back to docs](README.md)
