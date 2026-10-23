# Security

## What supareach does and does not touch

- **Offline by default.** Without `--db-url` it reads files under the directory you give it
  (source code, `supabase/migrations`, `supabase/config.toml`, `supabase/functions`) and
  writes only to the output directory, the baseline file and any `--sarif` file you name.
- **No network, no telemetry.** It makes no HTTP requests. `npx` itself downloads the package.
- **Never reads `.env` files** and never accepts a Supabase API key. It talks Postgres, not
  the Data API, so it never needs `service_role`.
- **`--db-url` is read-only.** The catalog read is one `psql` script that starts with
  `BEGIN TRANSACTION ... READ ONLY`, sets a statement timeout, selects from catalog views
  (`pg_proc`, `pg_class`, `pg_policies`, `pg_trigger`, `cron.job`, `storage.buckets`) and
  `has_*_privilege()`, and ends with `ROLLBACK`. Output that does not confirm a read-only
  transaction is rejected. The URL is split into `PG*` environment variables for `psql`, so
  the password is not visible in the process list; `SUPAREACH_DB_URL` keeps it out of
  supareach's own argv too.
- **Use a read-only role anyway.** Point it at a database built from your migrations in CI,
  or at a role with only `USAGE` on the relevant schemas and `SELECT` on `cron.job` and
  `storage.buckets`. Do not use a superuser connection string you would not paste into CI logs.
- **Plugins are code.** Modules listed in `plugins` are imported and run with your
  permissions. Only list files you trust, as with any build script.

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" on the
repository (Security tab), not in a public issue. Expect a reply within a week. Include the
version (`supareach --version`), the command line and a minimal reproduction.
