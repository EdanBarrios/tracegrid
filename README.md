# tracegrid

tracegrid — map every path from your app's code to its database, and catch what's exposed. Supabase today; Firebase next.

**What can a signed-in user reach that no code calls?**

A small CLI that maps how your app code reaches your Supabase project (tables, RPCs, edge
functions, storage buckets, cron jobs, auth hooks) and joins it with what the database
actually grants and protects. It reports the reverse direction most tools skip: functions
`anon` or `authenticated` can execute that nothing in the app, its edge functions, cron,
triggers, policies or views calls; edge functions with no caller; tables and views the client
reads without RLS. Static and offline by default. No AI, no telemetry. **v0.x, best effort:
read [Limitations](#limitations) before acting on a finding.** Not affiliated with Supabase.

![graph.html for the bundled demo app](https://raw.githubusercontent.com/EdanBarrios/tracegrid/main/docs/screenshot.png)

## Quickstart

```sh
cd your-supabase-app
npx --yes tracegrid@0.2.0            # scans the whole project, offline
```

It prints which Supabase project and code roots it used, then the top findings with
`file:line`. Full output goes to `./tracegrid-out/`. Try the bundled example:
`npx --yes tracegrid@0.2.0 --demo`.

If it warns about **0 code files, 0 Supabase call sites or 0 migrations, the result is empty,
not clean**: set `include` or `supabaseDir` in `tracegrid.config.json` (with `--check` such a
run exits 2).

| File | What |
|---|---|
| `report.md` | Findings with `file:line`, suppressions with their reasons, and everything it could not resolve, parse or apply |
| `graph.json` | `schema_version` 1. networkx node-link graph (`nodes`, `links` with `relation` and `confidence`: `extracted`, `inferred` or `ambiguous`), plus `rules`, `findings`, `suppressed`, `stats`, `project`, `warnings` |
| `graph.html` | One self-contained page that works offline. Findings sidebar grouped Fix / Review / Info with search and filters; a **dashboard** (exposure score, a role × surface reach matrix, the biggest holes drawn as one-line paths, findings by rule, top folders by database touchpoints, tables that rely on Supabase's legacy default grants, and scan coverage); a **path view** that shows a selected finding's neighbourhood in columns (Code, Entry points, Database, Roles), including "no caller in code"; a **full map** with folders and schema+kind groups collapsed until clicked; and an optional **3D** showcase. |

The 3D view is the only thing that touches the network: on click it loads one pinned library,
`3d-force-graph@1.80.1` from jsDelivr, with a Subresource Integrity hash and
`crossorigin="anonymous"`. Nothing else is fetched and no data leaves the page. Offline, it
says so and the 2D views keep working. Deep links: `graph.html#f=<fingerprint>` (or `f=first`)
selects a finding and opens its path, `view=dash`, `view=path`, `view=map` or `view=3d` opens that view. Every colour, stroke, radius and font is a CSS variable in the THEME block at the top of the page's stylesheet.

## What it finds

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
  in trusted workflows (see [SECURITY.md](SECURITY.md)).

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

## Colourways

`graph.html` ships four colourways, each with a dark and a light variant: `signal` (the
default: red and amber), `graphite-amber` (soft gold and slate), `mono` and `mint`. Severity is never colour alone:
the glyphs ◆ Fix, ◇ Review and · Info always go with it. Pick one in the page (gear button in the
sidebar: colourway, light / dark / auto, auto-rotate for the 3D tab; saved in the browser's
localStorage), with `?colorway=mono` on the URL (beats the saved choice), or set the default baked
into the file with `"colorway": "mint"` in `tracegrid.config.json` or `--colorway mint` (the flag wins).
Unknown names fail with the list of valid ones. The palettes are the THEME block at the top of
`src/html.js`.

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

## CI: fail when things get worse

```sh
npx --yes tracegrid@0.2.0 --update-baseline      # writes tracegrid.baseline.json; commit it
npx --yes tracegrid@0.2.0 --check --no-output    # exit 1 on a new Fix finding not in the baseline
```

The baseline is a list of fingerprints (Fix and Review findings). By default `--check` fails on
any **Fix** finding not in it; `--check-level review` gates Fix and Review. Info never gates.
Fixing one finding and adding another still fails. Review baseline diffs like code: a pull
request controls the file (see SECURITY.md). `--update-baseline` only removes entries
from an existing baseline; adding needs `--force`. Exit codes: 0 clean, 1 new findings, 2 usage
or tool error, or an empty scan under `--check`.

GitHub Actions, hardened: read-only token, actions pinned by SHA, an exact tracegrid version,
no `--db-url` and no plugins on pull requests.

```yaml
name: tracegrid
on: pull_request
permissions:
  contents: read
jobs:
  tracegrid:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with: { node-version: 22 }
      - run: npx --yes tracegrid@0.2.0 --check --github --no-plugins
  # Optional code-scanning alerts, in their own job so only it gets security-events: write
  # (needs GitHub Code Security on private repositories).
  sarif:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with: { node-version: 22 }
      - run: npx --yes tracegrid@0.2.0 --no-output --no-plugins --sarif tracegrid.sarif
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with: { sarif_file: tracegrid.sarif }
```

Or use the composite action in this repository (`uses: EdanBarrios/tracegrid@<sha>` with
`version`, `args` and `sarif` inputs). Run `--db-url` checks from a trusted workflow (push to
the default branch, schedule), never from `pull_request`.

## Options

```
tracegrid [dir] [options]
tracegrid help | --demo
  --out <dir>  --config <file>  --baseline <file>  --db-url <url>
  --check [--check-level fix|review]  --update-baseline [--force]  --sarif <file>  --github  --no-output  --colorway <name>
  --allow-plugins | --no-plugins  --demo  -h/--help  -v/--version
```

`explain`, `path` and `init` are reserved for future subcommands.

## For coding agents

The repository ships a Claude Code plugin and a portable skill
([`skills/tracegrid/SKILL.md`](skills/tracegrid/SKILL.md)):

```sh
claude plugin marketplace add EdanBarrios/tracegrid
claude plugin install tracegrid@tracegrid
```

For other agents, paste [`docs/AGENTS.md`](docs/AGENTS.md) into your `AGENTS.md`.

## How it compares

Use these alongside it; they answer different questions.

- **Supabase Security Advisor / splinter** lints the database: for example, every SECURITY
  DEFINER function `authenticated` can execute. It cannot tell which ones the app uses;
  tracegrid narrows that to the ones with no caller anywhere.
- **supabase-grants-lint** and **eslint-plugin-supabase** check the code-to-table direction
  with types, in the editor. They do not cover RPC reachability, edge functions, cron or
  storage.
- **pgrls** and **`supabase db lint`** go deep on RLS and PL/pgSQL correctness from the
  database side, with no notion of callers.
- **Graphify**, knip, dependency-cruiser map code graphs; `graph.json` uses the same
  node-link shape so the graphs can be combined.

## Limitations

Read these before revoking anything.

- **"Nothing calls it" means "no call site tracegrid recognised".** Grep for the name before
  revoking. Static analysis, no type checker: findings are leads.
- **What is scanned:** see the summary line and the code roots it prints. Code outside
  `include`, in excluded folders, or generated at build time is invisible. Tests, stories and
  mocks do not count as callers by design.
- **Patterns it does not see:** calls in Vue/Svelte template expressions (outside `<script>`),
  names built from runtime data, wrappers more than one import hop away or behind
  higher-order functions, clients passed through dependency injection or framework context
  under an unrecognisable name, other languages (Python, Dart, Swift clients), and callers
  outside the repository (other services, the dashboard, partners).
- **`edge-service-role-before-auth` is a heuristic.** It reads function text, not control flow. It recognises a fixed set of gates (auth calls, webhook and HMAC verifiers, a caller-scoped RLS read that returns or throws, a hashed or opaque-key capability, a rate-limit RPC that returns early) and cannot tell whether a gate is correct or covers every branch. A gate it does not recognise looks like no gate; a recognised name is not proof of a check. Treat it as a prompt to verify that the function authorizes callers.
- **Unresolved names** are listed in `report.md`; when any could reach an "uncalled" function,
  that finding is a warning with a caveat rather than an error.
- **Schemas:** `exposedSchemas` defaults to `public`; `.schema(<dynamic>)` matches the name in
  any schema, ambiguously.
- **Receivers are judged by name and binding, not type.** A non-Supabase object named like a
  client (`client.rpc(...)`) can be mistaken for one; unknown receivers never create
  missing-* findings.
- **service_role** clients are recognised by the key expression (`SERVICE_ROLE`, `secret`) or a
  conventional name (`supabaseAdmin`); a privileged client created elsewhere under another name
  counts as a normal caller and can hide a finding.
- **Migration replay is lossy:** dashboard changes, dynamic SQL with runtime values, and
  extension-created objects are invisible or approximate (listed as not understood). Prefer
  `--db-url` for gating.
- **Parse failures** are listed in the console, `report.md` and SARIF; calls after a syntax
  error may be missing. Files over 2 MB are skipped.
- References inside SQL bodies are found by name (`inferred`), and `.rpc('f')` counts as
  calling every overload of `f`.

## Development

```sh
npm install
npm test                         # node:test; psql is faked, no database needed
node bin/tracegrid.js --demo
```

Node 20+, ESM, plain JavaScript. The only dependency is `typescript` (for its parser). See
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
