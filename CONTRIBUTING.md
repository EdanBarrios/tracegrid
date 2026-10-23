# Contributing

Thanks for helping. tracegrid is small on purpose: plain ESM JavaScript, `node:test`, one
runtime dependency (`typescript`, for its parser). Please keep it that way.

## Setup

```sh
npm install
npm test                         # node --test; psql is faked, no database needed
node bin/tracegrid.js --demo     # the bundled example
```

Node 20 or newer. CI runs Node 20/22/24 on Linux, macOS and Windows.

## The most useful contribution: a false positive or false negative

Open an issue with the template, or better, a PR that adds a failing test:

- **SQL** (grants, policies, RLS, replay): add a case to `test/sql-semantics.test.js` with the
  smallest migration that shows it. If the claim is about Postgres behaviour, say how you
  checked it (Postgres docs link, or a transaction you rolled back).
- **Code** (a call tracegrid misses or invents): add a case to `test/extraction.test.js`
  with the smallest source file.

Fixtures must be synthetic. Never paste code, schema or names from a private project.

## Rules of thumb

- A finding that would make someone revoke a grant must be right, or say why it might not
  be (caveat, lower level, `confidence: low`). Silent false negatives are worse than noise.
- Everything printed or written can contain names from the scanned project: route it
  through `src/safe.js` (`oneLine`, `mdCode`, `mdText`).
- Nothing reads outside the scanned root; nothing runs project code unless
  `--allow-plugins` was passed.
- Keep functions linear on input size; add a timing test for anything that loops on text.

## Releases

`CHANGELOG.md` first, then the version in `package.json`, `action.yml` and
`.claude-plugin/plugin.json`. Publish with `npm publish --provenance` from CI.
