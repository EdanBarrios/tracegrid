# Limitations

Read these before revoking anything.

- Catalog mode (`--db-url`) is tested on macOS and Linux; on Windows it needs psql.exe on PATH.
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

[Back to docs](README.md)
