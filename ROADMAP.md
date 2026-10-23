# Roadmap

Rough order, not promises. Comment on an issue or open one if something here (or missing
from here) matters to you.

## Next

- **Benchmarks.** Name the repositories in [BENCHMARKS.md](BENCHMARKS.md) and extend it to
  Review-tier precision.
- **`explain <name>`.** Every path to one table, RPC, edge function or bucket, from the
  command line.
- **`--fix=print`.** Print draft revoke / `security_invoker` migrations for Fix findings;
  never applied.
- **`--since <ref>`.** Report only findings introduced since a git ref, without a baseline.
- **More edge-function security rules.** Beyond `edge-service-role-before-auth` and
  `edge-request-controlled-fetch`.
- **Policy logic checks.** RLS policies that are always true, or that ignore `auth.uid()`.

## Later

- **Firebase.** Firestore and Realtime Database rules plus client SDK calls, same graph and
  tiers.
- Other backends (Hasura, PocketBase, plain Postgres + PostgREST) if there is demand.
