# Changelog

All notable changes. Versions follow semver; while 0.x, minor versions may break the config,
the rule contract or `graph.json` (whose `schema_version` is bumped when its shape breaks).

## 0.2.0

Renamed from supareach before the first release.

A correctness and safety release driven by five red-team reviews (security, SQL semantics,
code extraction, nine real repositories, launch readiness). Findings changed for most
projects: re-run `--update-baseline` after reviewing them.

### Tiers and the viewer (final pre-launch round)
- Every finding has a tier: **Fix** (high confidence; act on it), **Review** (same kinds of
  problem with a caveat, or a functional problem), **Info** (intended patterns). The tier is in
  `graph.json`, `report.md` (grouped by tier), SARIF (`sarifLevels`: fix=error, review=warning,
  info=note by default), annotations and the console, and never in the fingerprint.
- `--check` now gates only new **Fix** findings; `--check-level review` gates Fix and Review.
  The baseline still records Fix and Review fingerprints, so switching levels does not turn
  accepted findings into new ones.
- The console prints `Fix N · Review N · Info N`, lists Fix first (top 10 with `file:line`),
  and counts each rule by the level its findings actually have (it used to print the rule's
  default level, e.g. "30 error" for 30 warnings).
- New `graph.html`: findings sidebar by tier with search and filters; a path view (Code |
  Entry points | Database | Roles) for the selected finding; a full map with collapsed groups;
  an optional 3D showcase that lazy-loads a pinned library from jsDelivr with SRI.
- `graph.html` opens on a dashboard: exposure score, Fix / Review / Info and new / fixed since
  the baseline, a role x surface reach matrix (click a cell to filter), the five biggest holes as
  one-line paths, findings by rule, top folders by database touchpoints, tables that rely on the
  legacy default grants (2026-10-30), and scan coverage. Every edge has an arrowhead, is at least
  1.5px at 3:1 contrast, is dashed only when inferred or ambiguous, carries its relation in the
  path view and is routed around the boxes it would cross. Schematic look: node kinds are shapes
  (2D symbols and 3D geometry), colour is reserved for tiers, and every colour, stroke, radius and
  font is a variable in one THEME block. Nodes carry `privsByRole` and, under the legacy grant
  model, `defaultGrants` (privileges that exist only through Supabase's default grants).
- New review-tier rules: `edge-service-role-before-auth`, `edge-request-controlled-fetch`.
  A hashed-token capability counts as a gate only when one file hashes with sha-256 and
  compares in constant time, and the request token is read on the import chain from the
  entry point to that file.
- Tables the migrations alter, grant or give policies to but never create (their schema lives in
  a dump or `scripts/`) have unknown RLS: `client-table-without-rls` reports them as Review with
  low confidence instead of Fix, and a notice names the likely schema file. On the benchmark this
  removed 26 false Fix findings in two repositories.
- `exposedSchemas` defaults to `[api] schemas` in `supabase/config.toml` (multi-line TOML arrays
  are now parsed), so rules see functions and tables in every schema the Data API serves.
  Supabase's own `pgmq_public` and `graphql_public` are never reported as uncalled.
- A table or RPC name missing from `public` but defined in another exposed schema is linked to it
  as ambiguous instead of reported as `unknown-table` / `missing-rpc` (clients bound to a schema
  through factories, objects of clients or `SupabaseClient<_, "schema">`). On the benchmark this
  removed 57 false Review findings in one repository.
- service_role clients are recognised through helpers: functions that return a client (same file
  or imported, including a cached `let client` assigned inside), a key read into a local variable,
  client parameters whose every same-file caller passes a privileged client or whose type is
  `ReturnType<typeof factory>`, and wrappers that take the client as a parameter. A helper that can
  return a browser client stays a browser caller. On the benchmark this removed 20 false Review
  findings in one repository.
- A URL whose name continues with a runtime part (`/rest/v1/rpc/get_${kind}`,
  `/functions/v1/report-` + kind) is a name pattern, not a call to the literal prefix.

### Analysis fixes (final pre-launch round)
- Functions named in a `DO` block that creates or alters policies with `EXECUTE format(...)`
  (in the template or an argument) count as used by policies: never "revoke it".
- `FOR r IN SELECT ... FROM pg_proc WHERE proname IN ('a', 'b') LOOP EXECUTE format('revoke
  ...', r.oid::regprocedure)` is applied per name; with a `LIKE` pattern or an unknown list the
  functions it could touch are low confidence (Review).
- `DO` blocks: loops are expanded with nesting (FOREACH over a declared array variable, then
  pg_proc rows by that name, definer overloads only when the query filters on `prosecdef`);
  `grant/revoke execute` and `alter default privileges` inside a `DO` block are no longer
  mistaken for dynamic `EXECUTE`.
- Unresolved `.rpc()` sites through a service-role client no longer downgrade
  `exposed-uncalled-function` (they cannot need the anon/authenticated grant);
  `serviceRoleClient()`-style factories are recognised.
- Column-level grants (`grant select (a, b) on t`) count as table privileges; a column list
  built in a `DO` block makes `client-table-not-granted` low confidence; a column-level revoke
  no longer removes table-level privileges.
- Local wrappers (`const call = (fn: string) => db.rpc(fn)`, `useCallback` wrappers) whose call
  sites all pass literals no longer leave an unresolved site; parameter types that are literal
  unions through a type alias, `keyof typeof OBJ` or `(typeof ARR)[number]` resolve.
- Imports resolve through the nearest tsconfig.json / jsconfig.json `paths` (one level of
  `extends`) and workspace package names.
- Nuxt `serverSupabaseServiceRole(event)` and keys named `SERVICE_KEY` / `SUPABASE_SECRET` mark
  a client as privileged.
- SECURITY.md: the baseline file is PR-controlled; review its diffs.

### Default grants (decision)
- `supabaseDefaultGrants` now defaults to `"auto"`. Supabase CLI v2.106.0 treats an unset
  `[api] auto_expose_new_tables` as false and the key is removed on 2026-10-30, so neither
  model is safe to assume silently. `"auto"` uses the config.toml value when it is set;
  otherwise it replays migrations under the legacy defaults, because an existing project's
  tables already got those grants and replay of explicit GRANT / REVOKE / ALTER DEFAULT
  PRIVILEGES is applied on top either way, and it prints a notice (console, `report.md`,
  `graph.json#notices`) that tables added after 2026-10-30 need an explicit GRANT. Pick
  `"legacy"` or `"opt-in"` to silence it; `--db-url` reads the real ACLs.
- `client-table-not-granted` explains the opt-in model and is a review item, not an exposure.

### Security
- Plugins load only with `--allow-plugins`, which is refused on GitHub `pull_request` /
  `pull_request_target` events; `--no-plugins` skips them. Plugin paths must be inside the
  project.
- `psql` is resolved to an absolute path outside the project (never `node_modules/.bin` or a
  relative `PATH` entry); `TRACEGRID_PSQL` must be absolute. `?options=` is rejected,
  `PGOPTIONS` cleared, and the catalog transaction pins `search_path = pg_catalog, pg_temp`.
- Reads are confined to the project root (globs, `supabaseDir`, `migrations`,
  `functionsDir`; symlinks only when the target is inside).
- Console output, `report.md`, the step summary and SARIF escape project-derived text
  (no workflow-command or Markdown injection).
- Size caps: source and migration files over 2 MB, SQL statements over 256 KB are skipped and
  listed. Linear-time SQL splitter, reference scanner and hatch parser; `globToRegExp` no
  longer hangs on an unclosed `{`; `__proto__`/`constructor` keys in the config are dropped and
  unknown keys warn.

### Scan scope
- The default `include` is the whole project, including `.vue`, `.svelte` and `.astro` script
  blocks (with original line numbers) and `.mts`/`.cts`. Dot-directories and `node_modules`
  are never walked; `dist`/`build`/`out`/`ios`/`android` are skipped only at the root or next to
  a `package.json` (`outputDirs`). Stories and `__mocks__` are excluded like tests.
- The Supabase project is auto-detected from `**/supabase/config.toml` and named in the
  output; several require `supabaseDir`.
- 0 code files, 0 call sites, or 0 migrations without `--db-url` are loud warnings and make
  `--check` exit 2. Files with syntax errors, binary files and UTF-16 (decoded with a BOM)
  are reported in the console, `report.md` and SARIF.
- When unresolved dynamic `.rpc()` / `invoke` call sites could reach an "uncalled" function or
  edge function, the finding is downgraded to a warning with a caveat naming them.

### SQL semantics (migration replay)
- `ALTER DEFAULT PRIVILEGES` is modelled as Postgres does: a global layer and per-schema layers
  that only add. A per-schema revoke from PUBLIC no longer hides an exposed function.
- `supabaseDefaultGrants`: `"legacy"` | `"opt-in"` | `false` (default from `[api]
  auto_expose_new_tables` in config.toml, else legacy); `--db-url` reports the live
  `pg_default_acl`. Table and view grants are tracked.
- Role membership (`grant role to authenticated`) is inherited; `ALL FUNCTIONS` / `ALL
  PROCEDURES` / `ALL ROUTINES` touch only their kind; quoted identifiers throughout;
  `SET SCHEMA`; `BEGIN ATOMIC` bodies; index expressions; database-webhook trigger URLs.
- Only `<version>_name.sql` files are replayed, in numeric order, like the Supabase CLI.
- `DO` blocks: `EXECUTE` with literal text or literal `format()` arguments (also in loops over
  array literals) is applied. Other dynamic RLS/policy/grant SQL is a risky warning and makes
  RLS findings `confidence: low`. The old revoke-loop heuristic is gone.
- SQL references respect schema qualifiers and quoted case; DDL mentions of a function are not
  calls.
- Catalog mode checks schema `USAGE`, reads SQL-standard bodies, all table privileges,
  trigger and index definitions.

### Code extraction
- Scope-aware name resolution: shadowing, `let` reassignment, `as const` arrays and loops,
  `.map` over literals, object maps, enums, concatenation, template literals, imported constants
  through barrels and path aliases. Partially known names link ambiguously to matching
  functions.
- Receivers: destructured, bound, aliased and element-access `rpc` / `functions` / `storage`;
  `db: { schema }` and `.schema(<dynamic>)`; `.rpc`/`.from` on clearly non-Supabase receivers
  (knex, ethers, drizzle, rxjs) are ignored; unknown receivers never create missing-* findings.
- Wrappers: cross-file exported wrappers, generic hooks, class and object methods,
  destructured parameters; config wrappers take `{ "name", "arg" }`.
- PostgREST: computed fields and computed relationships in `select()`, embedded tables,
  realtime `postgres_changes`, raw `/rest/v1/...` URLs, concatenated and relative
  `/functions/v1/` URLs. Mock handlers (msw), help text and `if (false)` are not callers.
- service_role / secret-key clients are a separate caller kind (`-service` relations): they
  do not clear anon/authenticated findings and do not trigger browser-client rules.
- `[auth.hook.*]` in config.toml and database-webhook triggers count as callers.

### Rules
- New: `client-view-without-security-invoker` (error), `client-table-not-granted` (warning),
  `auth-hook-function-exposed` (warning).
- `exposed-uncalled-function`: SECURITY INVOKER and authenticated-only is a warning.
- `granted-helper-function`: SECURITY DEFINER helpers callable by anon, or with no caller that
  needs the grant, are warnings instead of notes.
- `client-table-without-rls` needs anon/authenticated privileges; `client-table-without-policies`
  fires when no permissive policy applies to the client roles.

### CLI, packaging
- Top findings with `file:line` in the terminal; `help`; extra positionals rejected;
  `explain`, `path` and `init` reserved; `--check` without a baseline explains what to do;
  `--demo` runs the bundled example from npx.
- `graph.html`: on graphs over 200 nodes, starts focused on findings and their neighbours with
  files grouped by folder; "show all"; clicking a node expands it; hint on an empty graph.
- `repository`, `homepage`, `bugs`; Node 20+; SARIF `informationUri` points at the repository.
- Composite `action.yml`, CI matrix, Claude Code plugin and skill, `docs/agents.md`,
  CONTRIBUTING and issue templates.

## 0.1.0

First public version, renamed from the internal working name.

### Added
- Rule contract `{ id, level, title, why, run({ graph, catalog, config, root }) }`, used by
  the core rules and by plugins loaded from `plugins` in the config. Example plugin in
  `examples/demo-app`.
- `granted-helper-function` (note): executable by `anon`/`authenticated`, used only from SQL.
- Catalog mode `--db-url` (or `TRACEGRID_DB_URL`): reads the live schema through `psql` in
  a read-only transaction; wins over migration replay. Every finding records its `source`.
- Edge-function entry points: `entryPoints` with reasons, `// tracegrid: entry-point` hatch,
  and `verify_jwt = false` detected as an external entry (`autoEntryPoints`).
- In-source hatches: `names`, `ignore <rule> <reason>` (code and SQL), `entry-point`.
- `--sarif` (SARIF 2.1.0) and `--github` (annotations and step summary).
- Warning when skipped migration statements contain `GRANT`, `REVOKE` or `DROP POLICY`.
- `.schema('x')` qualifiers recorded; `exposedSchemas` config.

### Changed
- Baseline is a set of finding fingerprints (`<rule>:<subject>`); `--check` fails on any new
  fingerprint, not on rising counts. `--update-baseline` only shrinks unless `--force`.
- Ignores require `{ name, reason }`; bare strings are a config error.
- Functions are keyed by `name/arity`; same-arity overloads are merged.
- `graph.json` graph section uses networkx node-link names: `links`, `relation`, and
  `confidence` of `extracted`, `inferred` or `ambiguous`. `schema_version` stays 1.
- `findings` is a flat list of `{ rule, level, id, fingerprint, at, source, ... }`.
- Locations are repository-relative (`supabase/migrations/...`).
- Exit codes: 0 clean, 1 new findings, 2 usage or tool error.
