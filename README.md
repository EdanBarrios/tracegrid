<div align="center">

# tracegrid

**Map every path from your app's code to its database, and catch what's exposed but never used.**

[![npm](https://img.shields.io/npm/v/tracegrid)](https://www.npmjs.com/package/tracegrid)
[![CI](https://github.com/EdanBarrios/tracegrid/actions/workflows/ci.yml/badge.svg)](https://github.com/EdanBarrios/tracegrid/actions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Supabase · Firebase next](https://img.shields.io/badge/Supabase-Firebase%20next-3ecf8e)

<img src="docs/tracegrid.gif" alt="tracegrid: dashboard, path view and 3D map of the bundled demo app" width="900">

</div>

Static, offline, no AI, no telemetry. On 20 public Supabase apps, 111 of 113 Fix findings held up when checked by hand ([benchmarks](BENCHMARKS.md)). v0.x, best effort: read [Limitations](#limitations) before acting on a finding.

## What it finds

| Finding | Example | Tier |
|---|---|---|
| Exposed function nothing calls | `internal_cleanup()` executable by `anon`, no caller | Fix |
| Client-read table without RLS | `from('audit_log')` with RLS off | Fix |
| Owner-rights view over RLS tables | client reads a view without `security_invoker` | Fix |
| Missing RPC or edge function | `.rpc('get_totals')` not in the schema | Review |
| Edge function with no caller | `functions/old-sync` never invoked | Review |

All rules, tiers and examples: [docs/rules.md](docs/rules.md).

## Quickstart

```sh
npx tracegrid --demo
cd your-app && npx tracegrid
```

Output goes to `./tracegrid-out/` (`report.md`, `graph.json`, `graph.html`); see [Output](docs/output.md).

## Use it in CI

```yaml
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
      - run: npx --yes tracegrid@0.2.1 --check --github --no-plugins
```

`--check` fails on any new Fix finding not in `tracegrid.baseline.json` (create it with `--update-baseline`). SARIF and more: [docs/ci.md](docs/ci.md).

## Use it with Claude Code

```sh
claude plugin marketplace add EdanBarrios/tracegrid
claude plugin install tracegrid@tracegrid
```

## How it works

- Replays your Supabase migrations (or reads the live catalog with `--db-url`) to learn tables, functions, grants and RLS.
- Parses your code with the TypeScript parser to find `.from`, `.rpc`, `functions.invoke` and storage calls.
- Joins the two into one graph and reports exposure with no caller, in the reverse direction most tools skip.
- Writes `report.md`, `graph.json` and an offline `graph.html`.

## Limitations

- "Nothing calls it" means no call site tracegrid recognised; grep before revoking. [Details](docs/limitations.md)
- Static analysis without a type checker: findings are leads.
- Dynamic names, other languages and callers outside the repo are invisible.
- Migration replay is lossy; prefer `--db-url` for gating.
- `edge-service-role-before-auth` is a heuristic.
- Catalog mode (`--db-url`) is tested on macOS and Linux; on Windows it needs psql.exe on PATH.

[Docs](docs/README.md) · [Configuration](docs/configuration.md) · [Rules](docs/rules.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Benchmarks](BENCHMARKS.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md)

Not affiliated with Supabase. MIT © Edan Barrios.
