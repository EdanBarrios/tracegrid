# CI

```sh
npx --yes tracegrid@0.2.1 --update-baseline      # writes tracegrid.baseline.json; commit it
npx --yes tracegrid@0.2.1 --check --no-output    # exit 1 on a new Fix finding not in the baseline
```

The baseline is a list of fingerprints (Fix and Review findings). By default `--check` fails on
any **Fix** finding not in it; `--check-level review` gates Fix and Review. Info never gates.
Fixing one finding and adding another still fails. Review baseline diffs like code: a pull
request controls the file (see [SECURITY.md](../SECURITY.md)). `--update-baseline` only removes entries
from an existing baseline; adding needs `--force`. Exit codes: 0 clean, 1 new findings, 2 usage
or tool error, or an empty scan under `--check`.

GitHub Actions, hardened: read-only token, actions pinned by SHA, an exact tracegrid version,
no `--db-url` and no plugins on pull requests.

```yaml
name: tracegrid
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
  # Optional code-scanning alerts, in their own job so only it gets security-events: write
  # (needs GitHub Code Security on private repositories).
  sarif:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with: { node-version: 22 }
      - run: npx --yes tracegrid@0.2.1 --no-output --no-plugins --sarif tracegrid.sarif
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with: { sarif_file: tracegrid.sarif }
```

Or use the composite action in this repository (`uses: EdanBarrios/tracegrid@<sha>` with
`version`, `args` and `sarif` inputs). Run `--db-url` checks from a trusted workflow (push to
the default branch, schedule), never from `pull_request`.

[Back to docs](README.md)
