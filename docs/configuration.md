# Configuration

## Where the schema comes from

- **Migrations (default).** The Supabase project is auto-detected (`**/supabase/config.toml`)
  and its `migrations/<version>_name.sql` files are replayed in version order, like the
  Supabase CLI. The replay models tables, views, functions and overloads, grants and revokes
  including role membership and `ALTER DEFAULT PRIVILEGES` (global and per-schema layers, as
  Postgres does), table grants, RLS, policies, triggers, `cron.schedule`, and `EXECUTE` in `DO`
  blocks when its text is fully known. Statements it skips are listed; if any touch grants,
  policies or RLS it warns that grant-based findings may be wrong.
- **Default grants.** Supabase historically granted new tables and functions in `public` to
  anon/authenticated/service_role (per schema). From 2026-10-30 new tables are not exposed to
  the Data API by default, and Supabase CLI v2.106.0 already treats an unset
  `[api] auto_expose_new_tables` as false. `supabaseDefaultGrants` is `"auto"` (default),
  `"legacy"`, `"opt-in"` or `false` (vanilla Postgres). `"auto"` uses
  `auto_expose_new_tables` from config.toml when it is set; when it is not, it does not guess
  silently: it replays the migrations under the legacy defaults (an existing project's tables
  keep the grants they already got) and prints a one-line notice that tables added after
  2026-10-30 need an explicit GRANT. Explicit grants, revokes and `ALTER DEFAULT PRIVILEGES`
  in migrations always apply on top. Catalog mode reads the real ACLs and prints the live model.
- **Live catalog (`--db-url`).** Reads `pg_proc` with `has_function_privilege` (and schema
  `USAGE`), table privileges, RLS, policies, triggers, indexes, `pg_default_acl`, `cron.job`
  and `storage.buckets` through `psql` inside a read-only transaction ending in `ROLLBACK`. The
  catalog wins; migrations only supply `file:line`. **Prefer this mode when you can**, and only
  in trusted workflows (see [SECURITY.md](../SECURITY.md)).

```sh
TRACEGRID_DB_URL="postgresql://readonly_user:...@host:5432/postgres" npx --yes tracegrid@0.2.0
```

It never asks for a Supabase API key: it talks Postgres, not the Data API.

## What it reads in code

The whole project by default (`ts`, `tsx`, `js`, `jsx`, `mjs`, `cjs`, `mts`, `cts`, and the
script parts of `vue`, `svelte`, `astro`), excluding tests, stories, mocks, `node_modules`,
dot-directories, and build output next to a `package.json`. With the TypeScript parser (syntax
only, no type checker) it records:

- `.from('t')` with the chained operation, `.rpc('f')`, `functions.invoke('name')`,
  `.storage.from('bucket')`, through aliases, destructuring (`const { rpc } = supabase`),
  `.bind`/`.call`/`.apply`, `supabase['rpc']`, `.schema('x')` and
  `createClient(url, key, { db: { schema } })`.
- PostgREST `select()` strings: embedded tables, computed fields and computed relationships;
  realtime `postgres_changes`; raw `/rest/v1/rpc/<fn>`, `/rest/v1/<table>` and
  `/functions/v1/<name>` URLs, including concatenation and `new URL('functions/v1/x', base)`.
- Names from literals, constants (scope-aware), `let` reassignments, `as const` arrays and
  loops, object maps, enums, concatenation, and constants imported across files (barrels,
  `@/` / `~/` / `$lib/`, `paths` from the nearest tsconfig.json / jsconfig.json above the
  importing file with one level of `extends`, and workspace packages by their package.json
  `name`). Partially known names (`'fn_' + x`) link
  ambiguously to every matching function.
- Wrappers: same-file and exported functions, hooks, class and object methods, and
  destructured parameters that pass a name to a Supabase call; others go in `wrappers`.
- Clients created with a service_role / secret key are tracked separately: their calls keep a
  function "called", but do not justify an anon/authenticated grant and do not count as browser
  reads.
- `[auth.hook.*]` in config.toml and database-webhook triggers count as callers.

Anything it cannot resolve (`supabase.from(tableName)`) is **counted and listed, never
dropped**. A `// tracegrid: names a,b` comment above the call or its wrapper resolves it.

## Config: `tracegrid.config.json` (optional)

```json
{
  "supabaseDir": "apps/db/supabase",
  "include": ["**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts,vue,svelte,astro}"],
  "exclude": ["**/*.{test,spec}.{ts,tsx,js,jsx}", "**/__mocks__/**", "**/*.stories.*", "**/*.d.ts"],
  "exposedSchemas": ["public"],
  "supabaseDefaultGrants": "auto",
  "wrappers": { "rpc": ["callRpc", { "name": "rpcWithRetry", "arg": 1 }], "from": [], "invoke": [] },
  "entryPoints": [{ "name": "stripe-webhook", "reason": "Stripe calls it" }],
  "autoEntryPoints": true,
  "ignore": {
    "functions": [{ "name": "partner_sync", "reason": "called by a partner over the Data API" }],
    "findings": [{ "id": "unknown-table:legacy_view", "reason": "created by the analytics job" }]
  },
  "plugins": ["./.github/tracegrid-rules.mjs"]
}
```

Every ignore and entry point needs a `reason`; a bare string is a config error. Unknown keys
warn. Paths must stay inside the project. `ignore` also has `edgeFunctions`, `tables` and
`rpcs` lists. `migrations` and `functionsDir` override the auto-detected directories.
`sarifLevels` (default `{ "fix": "error", "review": "warning", "info": "note" }`) sets the
SARIF and GitHub annotation level per tier; `"none"` drops a tier's annotations.

**Edge-function entry points.** Webhooks, OAuth callbacks and health checks have no caller in
your code. Declare them in `entryPoints`, or put `// tracegrid: entry-point <reason>` in the
function. With `autoEntryPoints` (default on), `verify_jwt = false` functions are entry points.

**In-source hatches** (greppable):

```ts
// tracegrid: names tasks, projects            resolve a dynamic name on the next line / wrapper
// tracegrid: ignore missing-rpc <reason>      silence a rule for the call on this or the next line
// tracegrid: entry-point <reason>             in an edge function: called from outside
```
```sql
-- tracegrid: ignore exposed-uncalled-function <reason>   applies to the next create/alter
```

## Plugins

Project rules use the same contract as the core rules. **Plugins are code from the
repository: they load only with `--allow-plugins`, which is refused on pull-request events.**

```js
// .github/tracegrid-rules.mjs
export const rules = [{
  id: 'acme/no-client-writes-to-ledger',
  level: 'error',
  title: 'Client code writes to the ledger',
  why: 'Ledger rows are written by the billing edge function only.',
  run({ graph }) {
    return graph.links
      .filter((l) => l.relation === 'from' && l.target === 'table:ledger'
        && graph.node(l.source)?.side === 'client'
        && l.ops.some((op) => ['insert', 'update', 'upsert', 'delete'].includes(op)))
      .map((l) => ({ id: 'ledger', at: l.at[0] }));
  },
}];
```

`graph` has `nodes`, `links`, `node(id)`, `incoming(id)`, `outgoing(id)`; `catalog` is the
normalised schema. See `examples/demo-app/tracegrid-rules.mjs`.

## Options

```
tracegrid [dir] [options]
tracegrid help | --demo
  --out <dir>  --config <file>  --baseline <file>  --db-url <url>
  --check [--check-level fix|review]  --update-baseline [--force]  --sarif <file>  --github  --no-output  --colorway <name>
  --allow-plugins | --no-plugins  --demo  -h/--help  -v/--version
```

`explain`, `path` and `init` are reserved for future subcommands.

[Back to docs](README.md)
