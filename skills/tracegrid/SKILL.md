---
name: tracegrid
description: Map how an app's code reaches its backend and find surface a signed-in or anonymous user can reach that no code calls. Supabase (tables, RPCs, edge functions, storage, cron, auth hooks, grants, RLS) and Firebase (Firestore, Storage and Realtime Database Security Rules, Cloud Functions, Dart and JS/TS clients). Use when the user asks who calls a table, RPC, collection path or function; what breaks if a grant, function, table, rule or policy is revoked, dropped or renamed; whether an RPC, edge function or callable function is dead; for a Supabase or Firebase security review; or before changing grants, policies, Security Rules or functions. Needs supabase/migrations (or a Postgres URL) or firebase.json / a rules file.
allowed-tools: Bash(npx --yes tracegrid@0.2.1:*), Bash(npx tracegrid:*), Read, Grep, Glob
---

# tracegrid

`tracegrid` is a static, offline CLI. For Supabase it reads supabase-js call sites in the app and
edge functions and replays the migrations (or reads a live catalog with `--db-url`). For Firebase
it reads the Security Rules and the Firestore, Storage and callable-function references in Dart
and JS/TS. Either way it writes a graph plus findings. It never needs an API key and makes no network calls.

## 1. Run it

From the project root:

```sh
npx --yes tracegrid@0.2.1 --out .tracegrid
```

- It scans the whole project (`.vue`, `.svelte` and `.astro` script blocks included) and
  auto-detects the platform: a Supabase directory (`**/supabase/config.toml`), else
  `firebase.json` or a rules file at the root (`platform` and `firebaseJson` in the config pick
  one explicitly). The first lines name the
  Supabase project and the code roots it scanned; check they are the right ones.
- **If it warns `0 code files`, `0 Supabase call sites` or `0 migrations` (Firebase: no rules
  paths or call sites), the result is empty, not clean.** Say so and fix `include` /
  `supabaseDir` / `firebaseJson` in `tracegrid.config.json` before answering. With several Supabase projects it stops and asks for `supabaseDir`.
- If the config lists `plugins`, run with `--no-plugins`. Never pass `--allow-plugins`:
  plugins are code from the repository.
- Catalog mode is exact; migration mode is best effort. Use `--db-url` only if the user gives
  you a URL or `TRACEGRID_DB_URL` is already set. Never ask for, print or store a password,
  and never use a `service_role` key (tracegrid does not take one).
- Findings have a `tier`: `fix` (act on it), `review` (check the caveat in `note` first),
  `info` (intended patterns, such as helpers RLS policies need). Start with `fix`.
- Exit codes: 0 ran, 1 new Fix findings with `--check` (Fix or Review with `--check-level review`), 2 usage/tool error or an empty scan with
  `--check`. Without `--check`, findings still exit 0.

For a quick answer without opening files, add `--json`: stdout is one JSON object (`tiers`,
`findings` with `tier`, `rule`, `id`, `at` = `file:line`, `note`, `new` when a baseline exists;
`scope_problems`, `warnings`) and the usual text goes to stderr. A non-empty `scope_problems`
means the scan is empty, not clean. `--json` still writes the files under `--out`.

If the user keeps `graph.html` open, `tracegrid --serve` (optionally `--watch`) serves it on
`127.0.0.1` with a Refresh button and also serves `/graph.json` and `/report.md`. Do not start
it yourself unless asked; it runs until stopped.

Add `.tracegrid/` to `.gitignore` if it is not there. Do not commit generated output.

## 2. Read the output (do not read graph.html)

- `.tracegrid/report.md`: findings with `file:line`, suppressions with reasons, unresolved
  dynamic names, SQL it could not parse, dynamic SQL it applied, files it skipped. Read this
  first for review questions.
- `.tracegrid/graph.json`: `nodes` (`id` like `table:invoices`, `fn:next_invoice_number/1`,
  `edge:send-invoice`, `bucket:avatars`, `cron:nightly-digest`, `file:src/x.ts`; Firebase:
  `table:firestore:/teams/{teamId}`, `table:storage:storage:/avatars/{uid}/{file}`,
  `edge:<Cloud Function name>`), `links`
  (`source`, `target`, `relation`, `confidence` = `extracted|inferred|ambiguous`, `ops`,
  `at` = list of `file:line`), `findings`, `suppressed`, `stats`, `warnings`, `project`.
  Query it with a one-liner instead of reading it whole:

```sh
# who calls X (incoming links), with call sites
node -e 'const g=require("./.tracegrid/graph.json"),id=process.argv[1];for(const l of g.links.filter(l=>l.target===id))console.log(l.source,l.relation,l.ops.join(","),l.confidence,l.at.slice(0,5).join(" "))' 'fn:next_invoice_number/1'
# what X touches (outgoing)
node -e 'const g=require("./.tracegrid/graph.json"),id=process.argv[1];for(const l of g.links.filter(l=>l.source===id))console.log(l.target,l.relation,l.ops.join(","),l.at.slice(0,5).join(" "))' 'edge:send-invoice'
# find node ids by name
node -e 'const g=require("./.tracegrid/graph.json");for(const n of g.nodes.filter(n=>n.id.includes(process.argv[1])))console.log(n.id,n.type)' invoice
```

Relations: `rpc`, `from`, `invoke`, `storage` (code); the same with `-service` for calls
through a service_role / secret-key client; `from-weak` for `.from()` on a receiver that may
not be Supabase; `sql-call`, `policy-uses`, `view-uses`, `default-uses`, `index-uses`,
`trigger`, `cron`, `webhook`, `auth-hook`, `entry-point`, `dynamic-sql`. Firebase uses `from`
(Firestore and Realtime Database), `storage`, `invoke` (`httpsCallable`), `trigger` and
`entry-point`; `from-service` is the Admin SDK, which bypasses Security Rules.

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

**Firebase security review.** Start with the Fix rules (`firebase-rules-public-write`,
`firebase-rules-open-catch-all`, `firestore-self-writable-access-field`,
`firestore-rule-unused`), then Review. A rule path nothing uses is exposure the app does not need:
the fix is to tighten or delete the rule, drafted for the user to apply. Callers outside the
repository (admin apps, older app versions) are invisible, so say so before suggesting a removal.

**Supabase security review.** Report errors first (`exposed-uncalled-function`,
`client-table-without-rls`, `client-view-without-security-invoker`, `missing-rpc`,
`missing-edge-function`), then warnings. For each: what it is, `file:line`, the source
(`migrations` or `catalog`), any `note` (caveats such as unresolved callers or low
confidence), and the suggested fix. Findings are leads from static analysis, not proof; say
so once.

## 4. Rules for you

- Never apply a migration, revoke or drop anything yourself. Draft it; the user applies it.
- Never edit `tracegrid.baseline.json` by hand or run `--update-baseline --force` unless the
  user asks; that hides findings from CI.
- To silence a false positive, propose an `ignore` entry in `tracegrid.config.json` with a
  real `reason`, or a `// tracegrid: ignore <rule> <reason>` hatch; do not delete code.
- Quote `file:line` from the output; do not guess locations.
