---
name: supareach
description: Map how a Supabase app's code reaches its database (tables, RPCs, edge functions, storage, cron, auth hooks) and find surface a signed-in or anonymous user can reach that no code calls. Use when the user asks who calls a table, RPC or edge function; what breaks if a grant, function, table or policy is revoked, dropped or renamed; whether an RPC or edge function is dead; for a Supabase security or RLS review; or before writing a migration that changes grants, policies or functions. Requires a project with supabase/migrations or a Postgres URL.
allowed-tools: Bash(npx --yes supareach@0.2.0:*), Bash(npx supareach:*), Read, Grep, Glob
---

# supareach

`supareach` is a static, offline CLI. It reads supabase-js call sites in the app and edge
functions, replays the Supabase migrations (or reads a live catalog with `--db-url`), and
writes a graph plus findings. It never needs an API key and makes no network calls.

## 1. Run it

From the project root:

```sh
npx --yes supareach@0.2.0 --out .supareach
```

- It scans the whole project (`.vue`, `.svelte` and `.astro` script blocks included) and
  auto-detects the Supabase directory (`**/supabase/config.toml`). The first lines name the
  Supabase project and the code roots it scanned; check they are the right ones.
- **If it warns `0 code files`, `0 Supabase call sites` or `0 migrations`, the result is
  empty, not clean.** Say so and fix `include` / `supabaseDir` in `supareach.config.json`
  before answering. With several Supabase projects it stops and asks for `supabaseDir`.
- If the config lists `plugins`, run with `--no-plugins`. Never pass `--allow-plugins`:
  plugins are code from the repository.
- Catalog mode is exact; migration mode is best effort. Use `--db-url` only if the user gives
  you a URL or `SUPAREACH_DB_URL` is already set. Never ask for, print or store a password,
  and never use a `service_role` key (supareach does not take one).
- Exit codes: 0 ran, 1 new findings with `--check`, 2 usage/tool error or an empty scan with
  `--check`. Without `--check`, findings still exit 0.

Add `.supareach/` to `.gitignore` if it is not there. Do not commit generated output.

## 2. Read the output (do not read graph.html)

- `.supareach/report.md`: findings with `file:line`, suppressions with reasons, unresolved
  dynamic names, SQL it could not parse, dynamic SQL it applied, files it skipped. Read this
  first for review questions.
- `.supareach/graph.json`: `nodes` (`id` like `table:invoices`, `fn:next_invoice_number/1`,
  `edge:send-invoice`, `bucket:avatars`, `cron:nightly-digest`, `file:src/x.ts`), `links`
  (`source`, `target`, `relation`, `confidence` = `extracted|inferred|ambiguous`, `ops`,
  `at` = list of `file:line`), `findings`, `suppressed`, `stats`, `warnings`, `project`.
  Query it with a one-liner instead of reading it whole:

```sh
# who calls X (incoming links), with call sites
node -e 'const g=require("./.supareach/graph.json"),id=process.argv[1];for(const l of g.links.filter(l=>l.target===id))console.log(l.source,l.relation,l.ops.join(","),l.confidence,l.at.slice(0,5).join(" "))' 'fn:next_invoice_number/1'
# what X touches (outgoing)
node -e 'const g=require("./.supareach/graph.json"),id=process.argv[1];for(const l of g.links.filter(l=>l.source===id))console.log(l.target,l.relation,l.ops.join(","),l.at.slice(0,5).join(" "))' 'edge:send-invoice'
# find node ids by name
node -e 'const g=require("./.supareach/graph.json");for(const n of g.nodes.filter(n=>n.id.includes(process.argv[1])))console.log(n.id,n.type)' invoice
```

Relations: `rpc`, `from`, `invoke`, `storage` (code); the same with `-service` for calls
through a service_role / secret-key client; `from-weak` for `.from()` on a receiver that may
not be Supabase; `sql-call`, `policy-uses`, `view-uses`, `default-uses`, `index-uses`,
`trigger`, `cron`, `webhook`, `auth-hook`, `entry-point`, `dynamic-sql`.

## 3. Answer the question

**"Who calls X?"** List incoming links grouped by side (client file, edge function, cron,
trigger, policy, view, auth hook, other SQL function), each with `file:line` and confidence.
Say how many are `inferred` or `ambiguous`, and whether report.md lists unresolved dynamic
names of the same kind (a dynamic `.rpc(name)` could be a hidden caller).

**"What breaks if I revoke / drop / rename Y?"**
1. Resolve Y to node ids (a function name may have several arities; `.rpc('f')` counts as
   calling every overload).
2. Collect every incoming link. For a revoke from `authenticated`/`anon`, the breaking
   callers are client files and edge functions that use the user's JWT (they run as the
   user). `-service` callers, cron, and SQL inside SECURITY DEFINER functions keep working;
   policies, views, defaults, index expressions and triggers or invoker functions that call
   Y run as the user and break. State which case each caller is in.
3. Check unresolved dynamic names and `ignore` entries; mention them as unknowns.
4. If nothing calls it, say the revoke looks safe on static evidence and give the statement
   as a draft: `revoke execute on function public.<name>(<arg types>) from anon, authenticated, public;`
   Postgres grants EXECUTE to PUBLIC by default, so revoke from `public` too, and for future
   functions use the two-layer form: `alter default privileges revoke execute on functions
   from public;` plus `alter default privileges in schema public revoke execute on functions
   from anon, authenticated;`.

**Security review.** Report errors first (`exposed-uncalled-function`,
`client-table-without-rls`, `client-view-without-security-invoker`, `missing-rpc`,
`missing-edge-function`), then warnings. For each: what it is, `file:line`, the source
(`migrations` or `catalog`), any `note` (caveats such as unresolved callers or low
confidence), and the suggested fix. Findings are leads from static analysis, not proof; say
so once.

## 4. Rules for you

- Never apply a migration, revoke or drop anything yourself. Draft it; the user applies it.
- Never edit `supareach.baseline.json` by hand or run `--update-baseline --force` unless the
  user asks; that hides findings from CI.
- To silence a false positive, propose an `ignore` entry in `supareach.config.json` with a
  real `reason`, or a `// supareach: ignore <rule> <reason>` hatch; do not delete code.
- Quote `file:line` from the output; do not guess locations.
