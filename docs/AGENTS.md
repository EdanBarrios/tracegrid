# AGENTS.md snippet

Paste this into your repository's `AGENTS.md` (or `CLAUDE.md`) so coding agents check
reachability before changing the Supabase surface.

```markdown
## Supabase reachability (supareach)

Before changing, revoking, dropping or renaming a Supabase table, RPC, policy, grant or edge
function, run `npx --yes supareach@0.2.0 --out .supareach` from the repo root and check callers:

- Read `.supareach/report.md` for findings (`file:line`). Do not read `graph.html`.
- Who calls X: incoming `links` in `.supareach/graph.json` whose `target` is the node id
  (`table:<name>`, `fn:<name>/<arity>`, `edge:<name>`, `bucket:<name>`). Example:
  `node -e 'const g=require("./.supareach/graph.json");for(const l of g.links.filter(l=>l.target===process.argv[1]))console.log(l.source,l.relation,l.at.join(" "))' fn:my_rpc/1`
- If the run warns about `0 code files`, `0 Supabase call sites` or `0 migrations`, the result
  is empty, not clean: fix `include` / `supabaseDir` in `supareach.config.json` first.
- Relations ending in `-service` are service_role callers: they keep working after a revoke
  from anon/authenticated. `confidence: ambiguous` links and the "Unresolved dynamic names"
  table in report.md are possible hidden callers.
- Findings are static-analysis leads. Draft revokes as migrations for review; never apply
  them, never edit `supareach.baseline.json` by hand, never pass `--allow-plugins`.
```
