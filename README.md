# supareach

**v0, best effort.** A small, offline CLI that maps how your app code reaches your
Supabase project (tables, RPCs, edge functions, storage buckets, cron jobs) and
cross-checks it against what your migrations actually grant and protect.

No AI, no network, no database connection. It reads your source files and
`supabase/migrations/*.sql`, and writes three files.

## Why

In a Supabase app the browser talks to Postgres directly, so your attack surface is
whatever PostgREST exposes: every table and every function `anon` or `authenticated`
can reach. Over time that drifts from what the app actually uses. supareach answers:

- Which functions can a signed-in (or anonymous) user call that **nothing in the app calls**?
- Which tables does the client query with **RLS off**, or RLS on and **no policies**?
- Which RPCs does the code call that **no migration defines**?
- Which edge functions have **no caller** (no `functions.invoke`, URL, or cron job)?
- Which storage buckets are referenced, and where?

It also knows Supabase's default grants: a new function in `public` is executable by
`anon` and `authenticated` unless you revoke it from them, and `revoke ... from public`
alone does not do that.

## 30-second quickstart

```sh
cd your-supabase-app
npx supareach            # scans ./src and ./supabase
open supareach-out/graph.html
```

Output in `./supareach-out/`:

| File | What |
|---|---|
| `report.md` | Findings, with file:line, plus everything it could not resolve or parse |
| `graph.json` | Nodes and edges (`confidence: extracted \| inferred`), findings, `schema_version` |
| `graph.html` | One self-contained page: force layout, search, click a node to see its edges, dark/light. Works offline. |

![screenshot placeholder](docs/screenshot.png)

Try it on the bundled example: `npx supareach examples/demo-app`.

## What it reads

**Code** (TypeScript compiler API, not regex), default `src/**` and `supabase/functions/**`,
`.ts .tsx .js .jsx .mjs .cjs`, tests excluded:

- `.from('table')` with the chained operation (`select/insert/update/delete/upsert`)
- `.rpc('fn')`, including `(supabase.rpc as any)('fn')`, `(supabase as any).rpc(...)`, multi-line calls
- `functions.invoke('name')` and any string containing `/functions/v1/<name>`
- `.storage.from('bucket')`
- Names given as a ternary or `||` of literals, a same-file `const`, or a parameter typed as a
  union of string literals (`fn: 'a' | 'b'`) are resolved and marked `inferred`.
- Same-file wrappers are inferred: `const rpc = (name) => supabase.rpc(name)` makes `rpc('x')`
  a call to `x`, transitively. Cross-file wrappers can be listed in config.
- Anything else (`supabase.from(tableName)`) is **counted and listed, never dropped**.

**Migrations**, replayed in filename order (latest wins): tables, views, functions and their
overloads (args, `security definer`), `create or replace`, renames, drops,
`enable/disable row level security`, policies (table, command, roles), `grant/revoke execute`
(per function, `all functions in schema`, `alter default privileges`), triggers,
`cron.schedule`/`unschedule` bodies (functions called, `net.http_post` to `/functions/v1/x`),
and simple `DO` blocks. Statements it does not understand are listed in the report.

**Edge functions**: every `supabase/functions/<name>/index.*` except `_shared` and `_*`;
`verify_jwt = false` from `supabase/config.toml` is shown as a hint that it is a webhook.

A function counts as "called" if code calls it via RPC, or a cron job, trigger, policy, view,
column default or another SQL function references it.

## Config: `supareach.config.json` (optional)

```json
{
  "include": ["src/**/*.{ts,tsx,js,jsx}", "supabase/functions/**/*.ts"],
  "exclude": ["**/node_modules/**", "**/*.test.*", "**/*.d.ts"],
  "migrations": "supabase/migrations",
  "functionsDir": "supabase/functions",
  "wrappers": { "rpc": ["callRpc"], "from": [], "invoke": [] },
  "supabaseDefaultGrants": true,
  "ignore": {
    "functions": ["called_by_a_partner_integration"],
    "edgeFunctions": ["stripe-webhook", "auth-hook"],
    "tables": [],
    "rpcs": []
  }
}
```

Webhooks, auth hooks and health checks have no caller by design: put them in
`ignore.edgeFunctions`.

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
supareach [dir] [--out dir] [--config file] [--baseline file]
          [--check] [--update-baseline] [--no-output]
```

## Limitations (read before acting on a finding)

- **Migrations are not the database.** Anything changed in the dashboard, by hand, or by
  a seed is invisible. Treat findings as leads and confirm against the live catalog
  (`pg_proc.proacl`, `pg_policies`, `cron.job`).
- Cron jobs created outside migrations are not seen, so an edge function only reached by
  such a job will show as uncalled.
- SQL is parsed with regexes over a small tokenizer. Dynamic SQL (`EXECUTE format(...)`)
  is reported, not executed. One common pattern, a `DO` loop that revokes/grants
  `execute on function %s` over a literal list of names, is applied heuristically and
  reported as such. References inside dynamic `DO` blocks count as callers (conservative).
- References in SQL bodies are found by name (`fn(`), ignoring comments and, unless the body
  uses `EXECUTE`, string literals. That is `inferred`, not proven.
- Only the `public` schema is treated as exposed. `.schema('other').from(...)` is recorded
  by table name only.
- Names built at runtime, cross-file constants and cross-file wrappers (unless configured)
  are unresolved; they are listed so you can check them, and a function reached only that
  way can appear as "nothing calls".
- Table-level grants (`grant select on table`) are not modelled; only RLS and policies.
- Views: whether a client-read view bypasses RLS (`security_invoker`) is recorded on the
  node but not yet reported as a finding.
- The HTML layout is a simple force simulation; large projects (1,000+ nodes) look like a
  hairball. Use search and click.

## Development

```sh
npm install
npm test           # node:test, no other dev dependencies
node bin/supareach.js examples/demo-app
```

Node 18+, ESM, plain JavaScript. The only dependency is `typescript` (for its parser).

## License

MIT, see [LICENSE](LICENSE).
