# Benchmarks

tracegrid on public repositories, October 2026: how many findings it reports, how many of them
hold up when a person reads the code, and how long it takes. [Supabase](#summary): 20
repositories. [Firebase](#firebase): 70 repositories in two rounds.

## Summary

- **Fix tier: 111 of 113 findings correct (98%).** Before the fixes this benchmark prompted
  (in 0.2.0), 109 of 137 were correct (80%).
- **Most correct findings are low impact.** They are real exposure nobody uses (a function anon
  can execute that no code calls), but rarely dangerous on their own. One finding lets an
  unauthenticated caller write rows (event and challenge-flag records) through a SECURITY
  DEFINER function; it is held back for private disclosure to the project.
- **Review tier is noisier and not fully verified.** 302 Review findings before the fixes, 219
  after. It is meant to be read, not gated on.
- **Runtime:** median 3.3 s per repository; 59 s for the largest (1,234 migrations, 13,454
  Supabase call sites).

## Method

- **Selection.** Among the 100 most-starred repositories with the `supabase` GitHub topic, 27
  are TypeScript / JavaScript with a `supabase/migrations` directory. 20 of them were picked
  before any were scanned, for a spread from 1-migration starters to monorepos with over a
  thousand; skipped were Supabase's own repositories (SDK and docs test fixtures) and five
  small ones.
- **Run.** `tracegrid <repo> --no-plugins`, defaults, migration replay (no `--db-url`), shallow
  clone at a fixed commit. Nothing from the repositories was executed.
- **Verification.** Every Fix finding was checked by reading the migrations and the code:
  is the object really reachable by `anon` / `authenticated` after all migrations, and does
  anything outside the database call it (any language, any directory, edge functions,
  scripts)? Verdicts cite `file:line`. Review findings were sampled in 9 repositories.
- **Correct** means the statement in the finding is true. **Impact** is separate: *high*
  (writes or reads data it should not, without a check), *low* (unused but harmless, or
  guarded inside the function), *benign* (exposure that is intentional).
- **Timing:** one run each on an Intel i5-1030NG7 laptop, Node 24.

## Results

Repositories are pseudonymous (R01-R20, largest first) until the private disclosure is
resolved; they will be named afterwards.

| Repo | Migrations | Call sites | Time 0.2.0 | Time now | Fix | Review | Fix findings, verified |
|---|---:|---:|---:|---:|---:|---:|---|
| R01 | 1,234 | 13,454 | 265.7 s | 59.4 s | 96 → 96 | 25 → 25 | 96 correct: 92 low impact, 4 SECURITY DEFINER with an in-body role guard |
| R02 | 551 | 13,338 | 35.7 s | 24.3 s | 22 → 0 | 28 → 49 | none (was 22 false: schema in a dump outside migrations) |
| R03 | 187 | 3,559 | 14.9 s | 15.2 s | 0 → 0 | 47 → 35 | none |
| R04 | 148 | 1,882 | 21.6 s | 8.0 s | 1 → 1 | 40 → 3 | 1 correct, low |
| R05 | 113 | 282 | 3.9 s | 2.7 s | 3 → 3 | 11 → 11 | 1 correct, low; 2 false (called from a separate UI repository) |
| R06 | 87 | 916 | 29.5 s | 19.4 s | 3 → 5 | 64 → 10 | 5 correct: 1 high (held back for private disclosure), 4 low |
| R07 | 56 | 812 | 15 s | 8.5 s | 4 → 0 | 39 → 41 | none (was 4 false: schema in scripts/) |
| R08 | 54 | 936 | 21.2 s | 6.3 s | 0 → 0 | 3 → 2 | none |
| R09 | 32 | 21 | 8.3 s | 2.9 s | 1 → 1 | 0 → 0 | 1 correct, benign (view over public data) |
| R10 | 29 | 57 | 4.8 s | 3.0 s | 2 → 2 | 3 → 1 | 2 correct: 1 low, 1 benign (intentionally public view) |
| R11 | 20 | 0 | 14.7 s | 12.7 s | 0 → 0 | 2 → 2 | none |
| R12 | 7 | 44 | 9.7 s | 3.2 s | 1 → 1 | 1 → 1 | 1 correct, low |
| R13 | 6 | 229 | 8.6 s | 4.4 s | 0 → 0 | 1 → 1 | none |
| R14 | 5 | 9 | 1.3 s | 1.0 s | 0 → 0 | 1 → 1 | none |
| R15 | 4 | 160 | 5.2 s | 3.3 s | 2 → 2 | 2 → 2 | 2 correct, low (cron-only functions) |
| R16 | 1 | 113 | 2.9 s | 2.1 s | 0 → 0 | 30 → 30 | none |
| R17 | 1 | 96 | 2 s | 1.6 s | 1 → 1 | 4 → 4 | 1 correct, low |
| R18 | 1 | 20 | 1.7 s | 1.3 s | 0 → 0 | 0 → 0 | none |
| R19 | 1 | 15 | 1.3 s | 1.0 s | 1 → 1 | 1 → 1 | 1 correct, low |
| R20 | 1 | 10 | 3.2 s | 2.0 s | 0 → 0 | 0 → 0 | none |

`Fix` and `Review` are counts before → after the fixes below. R11 uses an ORM rather than
supabase-js, so tracegrid sees no call sites there.

## What the benchmark changed

Each false positive was traced to a cause and fixed with a regression test:

- **Schema outside the migrations** (26 false Fix findings, R02 and R07). Tables created in a
  `pg_dump` baseline or a `scripts/` directory looked like tables with RLS off. Their RLS state
  is now *unknown*: Review, low confidence, and a notice names the file to look at.
- **Exposed schemas other than `public`** (R06). `[api] schemas` in `config.toml` was not read,
  so functions in other exposed schemas were invisible to every rule, and clients bound to a
  schema produced 57 false `unknown-table` / `missing-rpc` findings. This is also what surfaced
  the high-impact finding.
- **service_role clients behind helpers** (37 false Review findings, R04). A client created in
  a helper, cached in a module variable, or passed as a parameter was treated as a browser
  client.
- **Edge-function gates** (R10). Auth middleware wrappers and checks that return 401 / 403 in a
  helper were not recognised.
- **Speed.** Module resolution and declaration lookups are memoized: R01 went from 266 s to 59 s.

## Known gaps

- **Callers outside the repository** (R05's 2 false findings): a backend-only repository
  whose UI lives elsewhere. Use `ignore.functions` with a reason, or scan both.
- **Raw SQL callers over a direct Postgres connection** (Kysely `sql\`select f()\``, R01) are
  not seen as callers. It did not change any verdict here: that connection is not `anon` or
  `authenticated`, so those grants are still unneeded.
- **Edge functions deployed under an alias** (`[functions.x] entrypoint = "./functions/y/..."`)
  and invoked through string-built URLs (R05) show as uncalled (Review).
- **Review tier** in R03 and R16 is mostly `unknown-table` for schemas tracegrid cannot see
  (no `CREATE TABLE` in the migrations); `--db-url` resolves it.

## Reproduce

`node bin/tracegrid.js <repo> --no-plugins` on each repository at the listed commit. The
repository list, commits and per-finding verdicts are published here once the private
disclosure is resolved.

## Firebase

### Summary

- **Fix tier: 75 of 75 findings correct** across 70 public Firebase repositories (9,058 files),
  at the commit that ships Firebase support.
- **On a fresh sample, 38 of 45 before fixes (84%).** Round 1 drove the first fixes; round 2 was
  a new random sample the code had never seen, scanned and checked before changing anything. The
  7 misses had three causes (below), each fixed with a regression test.
- **What the Fix findings are:** 26 rules anyone can write through (update, delete, Storage
  uploads, Realtime Database paths), 8 catch-all rules opening the whole database, 18 cases where
  a user can grant themselves access by writing a field the rules trust (`role`, `isAdmin`,
  `organizationId`), and 23 rule paths open to clients that no client code uses.
- **0 rules statements** the parser could not read, across 1,616-line rules files, UTF-16 files
  and commented `firebase.json`.

### Method

- **Selection.** GitHub code search for `firestore.rules` files (queries on common rule patterns,
  storage rules, Realtime Database rules, and `cloud_firestore` in `pubspec.yaml` for Flutter
  apps); forks, repositories over 150 MB and, in round 2, repositories untouched since June
  2024 were dropped. Round 1: 57 candidates, round 2: a seeded random 110 of 420 new ones.
- **Kept:** repositories that are Firebase projects with rules and client call sites (no scope
  problems): 27 in round 1, 43 in round 2. The rest had no rules file, no Firebase calls, or
  were Supabase projects.
- **Checking.** Every Fix finding was read against the rules and the code: the rule text for
  rule findings, a search of all client code for the collection for "unused" findings, and the
  write rules plus every rule reading the field for self-grant findings. Review was sampled:
  callables without an auth check 8 of 8 correct, paths without a rule 12 of 12, unused paths at
  Review 7 of 8 (the miss: a custom wrapper class, now configurable with `wrappers.firestore`).
- Repositories stay pseudonymous; several have live exposure.

### Results

| | Round 1 | Round 2 (fresh) |
|---|---:|---:|
| Repositories / files | 27 / 2,424 | 43 / 6,634 |
| Fix findings, correct before fixes | 37 of 37 * | 38 of 45 |
| Fix findings, correct after | 37 of 37 † | 38 of 38 |
| Review / Info findings | 212 / 4 | 297 / 1 |

\* 5 of them (public create-only writes) were then moved to Review as a tier choice, not because
they were wrong. † Includes 5 from the self-grant rule, added after round 1 and checked then.

### What the benchmark changed

- **Encodings and lenient config** (round 1): UTF-16 rules files, `firebase.json` with comments
  or a BOM, and rules without `firebase.json` crashed or were skipped.
- **Cloud Functions export styles** (both rounds): `const f = onCall()` exported later,
  `export * as group`, `exports.group = require()`, object groups, `export const { a } = ns`
  and `export const a = obj.a`. One repository went from 34 "missing" functions to 3, which are
  real (the app calls functions that were renamed or removed).
- **Collection-group rules are not catch-alls** (round 2): `/{path=**}/comments/{id}` covers
  `comments` collections only.
- **Who counts as already privileged** (round 2): a write only admins pass, or only a fixed
  email, is not self-escalation; `(request.resource.data).role` after a helper is inlined is a
  real check.
- **Reference helpers** (round 2): Dart extensions on `FirebaseFirestore`
  (`shareLinksRef() => collection('shareLinks')`) and helper functions returning a reference
  are followed to their call sites.
- **Create-only public writes are Review** (round 1): contact forms and guest orders write that
  way on purpose.
- Multi-line receivers, `.html` inline scripts, and handler bodies running past their end were
  fixed in round 1.

### Known gaps

- Generic repository classes that take the collection name as a parameter stay unresolved;
  the unused-path findings they could reach drop to Review.
- Callers outside the repository (admin web apps, other mobile apps, older app versions) are
  invisible.
- Rules edited in the console and never committed are not seen.

