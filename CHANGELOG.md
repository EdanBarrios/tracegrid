# Changelog

All notable changes. Versions follow semver; while 0.x, minor versions may break the config,
the rule contract or `graph.json` (whose `schema_version` is bumped when its shape breaks).

## Unreleased (0.1.0)

First public version, renamed from the internal working name.

### Added
- Rule contract `{ id, level, title, why, run({ graph, catalog, config, root }) }`, used by
  the core rules and by plugins loaded from `plugins` in the config. Example plugin in
  `examples/demo-app`.
- `granted-helper-function` (note): executable by `anon`/`authenticated`, used only from SQL.
- Catalog mode `--db-url` (or `SUPAREACH_DB_URL`): reads the live schema through `psql` in
  a read-only transaction; wins over migration replay. Every finding records its `source`.
- Edge-function entry points: `entryPoints` with reasons, `// supareach: entry-point` hatch,
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
