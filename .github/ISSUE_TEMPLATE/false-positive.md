---
name: False positive
about: supareach reported something that is not true
labels: false-positive
---

**Finding** (rule and id, e.g. `exposed-uncalled-function:my_fn/1`):

**Why it is wrong** (who calls it, or why the grant/policy is fine):

**Smallest reproduction** (synthetic; no private code or schema):

```sql
-- migration
```

```ts
// call site
```

**Mode**: migrations / `--db-url`  ·  **Version**: `npx supareach --version`
