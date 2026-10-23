#!/usr/bin/env node
// Stand-in for psql in tests: records how it was called and prints a catalog fixture.
import fs from 'node:fs';
const input = fs.readFileSync(0, 'utf8');
if (process.env.FAKE_PSQL_LOG) {
  fs.writeFileSync(process.env.FAKE_PSQL_LOG, JSON.stringify({
    argv: process.argv.slice(2), stdin: input,
    env: { PGHOST: process.env.PGHOST, PGPORT: process.env.PGPORT, PGUSER: process.env.PGUSER, PGDATABASE: process.env.PGDATABASE, PGPASSWORD: process.env.PGPASSWORD, PGSSLMODE: process.env.PGSSLMODE },
  }));
}
if (process.env.FAKE_PSQL_FAIL) { process.stderr.write('psql: error: connection refused\n'); process.exit(2); }
process.stdout.write(fs.readFileSync(process.env.FAKE_PSQL_FIXTURE, 'utf8'));
