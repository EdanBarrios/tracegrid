# Documentation

| Page | Contents |
|---|---|
| [Configuration](configuration.md) | schema sources, what is read in code, config file, hatches, plugins, CLI options |
| [Rules](rules.md) | every rule, tier and example |
| [Output](output.md) | graph.json, report.md, graph.html, SARIF, colourways |
| [CI](ci.md) | baseline, `--check`, GitHub Actions, SARIF |
| [Limitations](limitations.md) | what tracegrid cannot see |
| [Coding agents](agents.md) | Claude Code plugin, AGENTS.md snippet |


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

## Development

```sh
npm install
npm test                         # node:test; psql is faked, no database needed
node bin/tracegrid.js --demo
npm run site                     # tracegrid.dev into site/dist (landing page + /demo)
npm run stats                    # adoption from public sources (npm, GitHub code search)
```

Node 20+, ESM, plain JavaScript. The only dependency is `typescript` (for its parser). See
[CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md) and [CHANGELOG.md](../CHANGELOG.md).

