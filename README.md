# supareach

**What can a signed-in user reach that no code calls?**

**v0, best effort.** A small CLI that maps how your app code reaches your Supabase
project (tables, RPCs, edge functions, storage buckets, cron jobs) and joins it with what
the database actually grants and protects. It reports the reverse direction nobody else
does: functions `anon` or `authenticated` can execute that nothing in the app, its edge
functions, cron, triggers, policies or views calls; edge functions with no caller; and
tables the client reads without RLS. No AI, no telemetry. Not affiliated with Supabase.

![graph.html for the bundled demo app](docs/screenshot.png)

## Quickstart

```sh
cd your-supabase-app
npx supareach                       # scans ./src and ./supabase, offline
open supareach-out/graph.html
```

Try it on the bundled example: `npx supareach examples/demo-app`.

Output in `./supareach-out/`:

| File | What |
|---|---|
| `report.md` | Findings with file:line, suppressions with their reasons, and everything it could not resolve or parse |
| `graph.json` | `schema_version` 1. Graph section in networkx node-link form (`nodes`, `links` with `relation` and `confidence`: `extracted`, `inferred` or `ambiguous`), so `networkx.node_link_graph(data, edges="links")` and Graphify-style tooling can load it; plus `rules`, `findings`, `suppressed`, `stats` |
| `graph.html` | One self-contained page: force layout, search, click a node to see its links, dark/light. No CDN. |

## What it finds

| Rule | Level | Meaning |
|---|---|---|
| `exposed-uncalled-function` | error | `anon`/`authenticated` can execute it and nothing references it |
| `granted-helper-function` | note | executable by those roles, no `.rpc()` caller, but used by a policy, view, trigger, cron job or other SQL. Needed for RLS helpers; often not for the rest |
| `client-table-without-rls` | error | client code queries a table with RLS off |
| `client-table-without-policies` | warning | RLS on, no policy: the client gets nothing back |
| `missing-rpc` | error | code calls an RPC the schema does not define |
| `unknown-table` | warning | code queries a table or view the schema does not define |
| `uncalled-edge-function` | warning | no `functions.invoke`, `/functions/v1/<name>` URL, cron job or SQL caller, and not declared an entry point |
| `missing-edge-function` | error | invoked, but no `supabase/functions/<name>/index.*` |

Functions are identified as `name/arity` (`next_invoice_number/1`). Each finding has a
stable fingerprint, `<rule>:<subject>`, and records whether it rests on migrations or the
live catalog.

## Where the schema comes from

- **Migrations (default).** `supabase/migrations/*.sql` replayed in order with a small
  hand-written parser: tables, views, functions and overloads, grants and revokes
  (including `alter default privileges` and Supabase's default grants to `anon` and
  `authenticated`), RLS, policies, triggers, `cron.schedule`. Zero setup, works on a
  checkout. **Best effort:** dynamic SQL in `DO` blocks, dashboard changes and anything not
  in a migration are invisible. Statements it skips are listed, and if any of them touch
  `GRANT`, `REVOKE` or `DROP POLICY` it warns that grant-based findings may be wrong.
- **Live catalog (`--db-url`).** Reads `pg_proc` with `has_function_privilege` for `anon`
  and `authenticated`, `pg_class.relrowsecurity`, `pg_policies`, triggers, `cron.job` and
  `storage.buckets`, through the `psql` client inside `BEGIN ... READ ONLY` ending in
  `ROLLBACK`. The catalog wins; migrations only supply file:line. **Gate CI on this mode
  when you can**: a revoke inside dynamic SQL, or one made in the dashboard, is enough to
  make migration replay report a function as exposed when it is not.

```sh
# A database built from your migrations (CI) or a read-only role on a real one.
npx supareach --db-url "postgresql://readonly_user:...@host:5432/postgres"
# or SUPAREACH_DB_URL=... npx supareach   (keeps the URL out of argv)
```

It never asks for a Supabase API key: it talks Postgres, not the Data API, so it never
needs `service_role`. It needs `psql` on PATH for this mode and no other dependency.

## What it reads in code

TypeScript compiler API (syntax only, no type check), default `src/**` and
`supabase/functions/**`, tests excluded:

- `.from('table')` with the chained operation, `.rpc('fn')` including
  `(supabase.rpc as any)('fn')` and multi-line calls, `functions.invoke('name')`, any string
  containing `/functions/v1/<name>`, `.storage.from('bucket')`.
- `.schema('x').from('t')` and `.schema('x').rpc('f')` are recorded as `x.t` / `x.f`.
- A same-file `const` resolves as `inferred`; a ternary, `||` or literal-union parameter as
  `ambiguous` (every candidate is recorded).
- Same-file wrappers are inferred (`const rpc = (n) => supabase.rpc(n)`); cross-file ones go
  in `wrappers` in the config.
- Anything else (`supabase.from(tableName)`) is **counted and listed, never dropped**. A
  `// supareach: names a,b` comment above the call or its wrapper resolves it.

## Config: `supareach.config.json` (optional)

```json
{
  "include": ["src/**/*.{ts,tsx,js,jsx}", "supabase/functions/**/*.ts"],
  "migrations": "supabase/migrations",
  "functionsDir": "supabase/functions",
  "exposedSchemas": ["public"],
  "wrappers": { "rpc": ["callRpc"], "from": [], "invoke": [] },
  "entryPoints": [{ "name": "stripe-webhook", "reason": "Stripe calls it" }],
  "autoEntryPoints": true,
  "ignore": {
    "functions": [{ "name": "partner_sync", "reason": "called by a partner over the Data API" }],
    "findings": [{ "id": "unknown-table:legacy_view", "reason": "created by the analytics job" }]
  },
  "plugins": ["./.github/supareach-rules.mjs"]
}
```

Every ignore and entry point needs a `reason`; a bare string is a config error. Suppressed
findings stay visible in the report with their reason. `ignore` also has `edgeFunctions`,
`tables` and `rpcs` lists.

**Edge-function entry points.** Webhooks, OAuth callbacks, auth hooks and health checks have
no caller in your code. Declare them in `entryPoints`, or put
`// supareach: entry-point <reason>` in the function. With `autoEntryPoints` (default on),
functions with `verify_jwt = false` in `supabase/config.toml` are treated as entry points
with that reason. Entry points are listed in the report so the reasons stay reviewable.

**In-source hatches** (greppable):

```ts
// supareach: names tasks, projects            resolve a dynamic name on the next line / wrapper
// supareach: ignore missing-rpc <reason>      silence a rule for the call on this or the next line
// supareach: entry-point <reason>             in an edge function: called from outside
```
```sql
-- supareach: ignore exposed-uncalled-function <reason>   applies to the next create/alter
```

## Plugins

Project rules use the same contract as the core rules and are baselined, ignored and
reported the same way:

```js
// .github/supareach-rules.mjs
export const rules = [{
  id: 'acme/no-client-writes-to-ledger',
  level: 'error',
  title: 'Client code writes to the ledger',
  why: 'Ledger rows are written by the billing edge function only.',
  run({ graph, catalog, config, root }) {
    return graph.links
      .filter((l) => l.relation === 'from' && l.target === 'table:ledger'
        && graph.node(l.source)?.side === 'client'
        && l.ops.some((op) => ['insert', 'update', 'upsert', 'delete'].includes(op)))
      .map((l) => ({ id: 'ledger', at: l.at[0] }));
  },
}];
```

`graph` has `nodes`, `links`, `node(id)`, `incoming(id)`, `outgoing(id)`; `catalog` is the
normalised schema (tables with policy text, functions with grants, cron, buckets). See
`examples/demo-app/supareach-rules.mjs`.

## CI: fail when things get worse

```sh
npx supareach --update-baseline      # writes supareach.baseline.json; commit it
npx supareach --check --no-output    # exit 1 if any finding is not in the baseline
```

The baseline is a list of finding fingerprints (`<rule>:<subject>`, e.g.
`exposed-uncalled-function:next_invoice_number/1`). `--check` fails on any error or
warning whose fingerprint is not in it, so fixing one finding and adding another still
fails. `--update-baseline` only removes entries from an existing baseline; adding needs
`--force`. Exit codes: 0 clean, 1 new findings, 2 usage or tool error.

GitHub Actions (annotations on the PR diff and a job summary, no permissions needed):

```yaml
name: supareach
on: pull_request
jobs:
  supareach:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes supareach@0 --check --github --sarif supareach.sarif
      # Optional: code scanning alerts. Needs `permissions: security-events: write`, and a
      # GitHub Code Security license on private repositories.
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: supareach.sarif }
```

## Options

```
supareach [dir] [--out dir] [--config file] [--baseline file] [--db-url url]
          [--check] [--update-baseline [--force]] [--sarif file] [--github] [--no-output]
```

## How it compares

Use these alongside it; they answer different questions.

- **Supabase Security Advisor / splinter** lints the database: for example, it flags every
  SECURITY DEFINER function `authenticated` can execute, which in a mature app can be
  hundreds. It cannot tell which ones the app uses; supareach narrows that to the ones with
  no caller anywhere, which is the list worth reviewing.
- **supabase-grants-lint** and **eslint-plugin-supabase** check the code-to-table direction
  ("will this `.from()` call be allowed?") and the 2026 table-grant changes, with types, in
  the editor. They do not cover RPC reachability, edge functions, cron or storage; the
  ESLint plugin skips `supabase/functions`.
- **pgrls** and **`supabase db lint`** go deep on RLS and PL/pgSQL correctness from the
  database side, with no notion of callers.
- **Graphify**, knip, dependency-cruiser map code graphs; none links supabase-js call sites
  to database objects. supareach's `graph.json` uses the same node-link shape so the graphs
  can be combined.

## Limitations (read before acting on a finding)

- **v0, best effort, static analysis.** Treat findings as leads. Migration mode is lossy
  (see above); prefer `--db-url`.
- References in SQL bodies are found by name (`fn(`), ignoring comments and, unless the body
  uses `EXECUTE`, string literals: `inferred`, not proven. In migration mode, references in
  dynamic `DO` blocks count as callers (conservative).
- Code calls resolve by name: `.rpc('f')` counts as calling every overload of `f`.
- Names built at runtime and cross-file constants are unresolved unless configured or
  hatched; a function reached only that way can appear uncalled. They are listed.
- Table-level grants are read in catalog mode but not yet reported; views running with
  owner rights (`security_invoker` off) are recorded, not yet reported.
- Only JS/TS clients. The HTML force layout gets crowded past ~1,000 nodes; use search.

## Development

```sh
npm install
npm test           # node:test; the psql layer is mocked, no database needed
node bin/supareach.js examples/demo-app
```

Node 18+, ESM, plain JavaScript. The only dependency is `typescript` (for its parser).
Security: see [SECURITY.md](SECURITY.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
