# Security

supareach is built to run in CI on pull requests, including pull requests from forks. In that
setting the PR author controls the config file, the migrations, every scanned source file and
even `node_modules/.bin`. The defaults below assume that.

## What supareach does and does not touch

- **Offline by default.** Without `--db-url` it reads files under the directory you give it and
  writes only to the output directory, the baseline file and any `--sarif` file you name. No
  network, no telemetry. (`npx` itself downloads the package.) `graph.html` works offline; only
  its optional 3D view, when you click it, loads `3d-force-graph@1.80.1` from jsDelivr with a
  Subresource Integrity hash and `crossorigin="anonymous"`. The page sends nothing anywhere.
- **Reads stay inside the project.** `include`/`exclude` globs, `supabaseDir`, `migrations` and
  `functionsDir` may not contain `..` or absolute paths. Symbolic links are followed only when
  their target is inside the project; a link to `/home/runner/...` is not read.
- **Never reads `.env` files** and never accepts a Supabase API key. It talks Postgres, not the
  Data API, so it never needs `service_role`.
- **Resource limits.** Source files over 2 MB, migration files over 2 MB and single SQL
  statements over 256 KB are skipped and listed (a warning, and SARIF notifications). The
  parsers are linear in input size.

## Recommendations

1. **Plugins only with `--allow-plugins`.** Modules in `plugins` are code from the repository
   and run with your environment (tokens, `SUPAREACH_DB_URL`). They load only with
   `--allow-plugins`, which is refused on GitHub `pull_request` and `pull_request_target`
   events; without the flag a config that lists plugins is an error (use `--no-plugins` to run
   without them). Plugin paths must be inside the project.
2. **`--db-url` only in trusted workflows** (push to your default branch, schedule, manual),
   never on `pull_request`. Use a read-only role: `USAGE` on the app schemas and `SELECT` on
   `cron.job` and `storage.buckets`, or a database built from your migrations. `psql` is
   resolved to an absolute path; a `psql` inside the project, under `node_modules` or found
   through a relative `PATH` entry is refused (`npx` puts the project's `node_modules/.bin`
   first on `PATH`). Set `SUPAREACH_PSQL` to an absolute path to choose one. `?options=` in the
   URL is rejected and `PGOPTIONS` is cleared, and the catalog transaction pins
   `search_path = pg_catalog, pg_temp` before any query, so a migration cannot shadow catalog
   functions through a role's `search_path`.
3. **Output is untrusted data.** Names in findings come from the PR. Console lines escape
   control characters and a leading `::` (no workflow-command injection); `report.md` and the
   job summary escape Markdown and HTML; `graph.html` escapes everything it renders; SARIF URIs
   are percent-encoded. Review the findings themselves, not only the summary counts.
4. **The baseline is pull-request controlled.** `supareach.baseline.json` lives in the
   repository, so a pull request can add its own new findings to it and `--check` will pass.
   Review baseline diffs like code (a CODEOWNERS entry on the file helps), and read the
   `--update-baseline` output, which lists every fingerprint it adds or removes, before
   committing it. `--update-baseline` refuses to add entries without `--force` for the same
   reason. In-source `supareach: ignore` hatches and `ignore` config entries are equally
   PR-controlled; they are listed with their reasons in `report.md`.
5. **Hardened Actions setup.** `permissions: contents: read` for the job, plus
   `security-events: write` only on the job that uploads SARIF; actions pinned by commit SHA;
   an exact supareach version (`npx --yes supareach@0.2.0`), not a range. See the README.

## What `--db-url` does

One `psql` script: `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`, `SET LOCAL
search_path = pg_catalog, pg_temp`, a statement timeout, selects from catalog views and
`has_*_privilege()`, and `ROLLBACK`. Output that does not confirm a read-only transaction is
rejected. The URL is split into `PG*` environment variables for `psql`, so the password is not
visible in the process list; `SUPAREACH_DB_URL` keeps it out of supareach's own argv too.

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" on the
repository (Security tab), not in a public issue. Expect a reply within a week. Include the
version (`supareach --version`), the command line and a minimal reproduction.
