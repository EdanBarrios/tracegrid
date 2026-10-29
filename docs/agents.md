# Coding agents

## Claude Code

The repository ships a Claude Code plugin and a portable skill
([`skills/tracegrid/SKILL.md`](../skills/tracegrid/SKILL.md)):

```sh
claude plugin marketplace add EdanBarrios/tracegrid
claude plugin install tracegrid@tracegrid
```

## Other agents: AGENTS.md snippet

Paste this into your repository's `AGENTS.md` (or `CLAUDE.md`) so coding agents check
reachability before changing the Supabase or Firebase surface.

```markdown
## Backend reachability (tracegrid)

Before changing, revoking, dropping or renaming a Supabase table, RPC, policy, grant or edge
function, or a Firebase Security Rule, Firestore/Storage path or Cloud Function, run
`npx --yes tracegrid@0.2.1 --json --out .tracegrid` from the repo root and check callers.
stdout is one JSON object (`tiers`, `findings` with `file:line`, `scope_problems`); the human
text goes to stderr.

- Read `.tracegrid/report.md` for findings (`file:line`), grouped Fix / Review / Info; start
  with Fix. Do not read `graph.html`.
- Who calls X: incoming `links` in `.tracegrid/graph.json` whose `target` is the node id
  (`table:<name>`, `fn:<name>/<arity>`, `edge:<name>`, `bucket:<name>`; Firebase:
  `table:firestore:<path>`, `table:storage:storage:<path>`, `edge:<function>`). Example:
  `node -e 'const g=require("./.tracegrid/graph.json");for(const l of g.links.filter(l=>l.target===process.argv[1]))console.log(l.source,l.relation,l.at.join(" "))' fn:my_rpc/1`
- A non-empty `scope_problems` (or a warning about `0 code files`, `0 call sites`, `0 migrations`)
  means the result is empty, not clean: fix `include` / `supabaseDir` / `firebaseJson` in
  `tracegrid.config.json` first.
- Relations ending in `-service` are service_role (Supabase) or Admin SDK (Firebase) callers:
  they keep working after a revoke from anon/authenticated or a rules change. `confidence: ambiguous` links and the "Unresolved dynamic names"
  table in report.md are possible hidden callers.
- Findings are static-analysis leads. Draft revokes as migrations for review; never apply
  them, never edit `tracegrid.baseline.json` by hand, never pass `--allow-plugins`.
```

## Keeping the dashboard current

`graph.html` is a file, so it goes stale after you edit code. For a live view:

```sh
npx tracegrid --serve --watch      # http://127.0.0.1:4777/
```

The page gets a Refresh button (↻) that re-scans the project and reloads; with `--watch` the
server re-scans when files change and the button lights up when new results are ready. The server
listens on 127.0.0.1 only, serves `/graph.json` and `/report.md` for agents that would rather
`curl`, never runs plugins unless `--allow-plugins` is given, and refuses requests with a foreign
Host header or from another origin. It runs until you stop it (Ctrl-C).
