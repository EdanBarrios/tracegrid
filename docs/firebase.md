# Firebase

tracegrid checks Firebase projects (Firestore, Storage, Realtime Database and Cloud Functions)
with the same graph, tiers, `report.md`, `graph.html`, SARIF, baseline and `--check` as Supabase.
It reads the repository only: no project access, no credentials, no network.

```sh
cd your-firebase-app && npx tracegrid
```

## What it reads

- **`firebase.json`** for the rules files and functions codebases it names. Without one,
  `firestore.rules`, `storage.rules` and `database.rules.json` at the root are used.
  Comments, trailing commas, BOMs and UTF-16 files are accepted, as the Firebase CLI does.
- **Security Rules.** Every `allow` in Firestore and Storage rules (nested `match`, `{var}`
  and `{var=**}` wildcards, rule functions with `let`) and every `.read` / `.write` in Realtime
  Database rules. Each is classified by who can pass its condition:
  `public` (anyone), `signed-in` (any signed-in user), `conditional` (an owner check, a field
  check, a `get()` lookup...) or `closed`. Rule functions are inlined; `||` takes the most
  permissive side, `&&` the least. Anything not fully understood is `conditional`, so findings
  that say "anyone" or "any signed-in user" only come from conditions tracegrid understands.
- **App code**, Dart (Flutter) and JavaScript / TypeScript, including inline scripts in
  `.html`:
  - Firestore references: `FirebaseFirestore.instance.collection('users').doc(uid)`, path
    strings (`'users/$uid/tasks'`), web v9 `collection(db, 'users', id, 'orders')`, `doc()`,
    `collectionGroup()`, v8 / compat chains, references kept in variables, getters, helper
    functions and Dart extensions on `FirebaseFirestore`.
  - Storage references: `FirebaseStorage.instance.ref('a').child('b')`, `ref(storage, 'a/b')`.
  - Callable functions: `httpsCallable('name')`, `httpsCallable(functions, 'name')`, wrappers
    such as `_call('name', payload)` (found automatically when a parameter is passed straight
    through), and `cloudfunctions.net/<name>` URLs.
  - Code under a functions codebase, or that imports `firebase-admin`, uses the Admin SDK,
    which bypasses rules: it is shown in the graph but never counts as a client caller.
- **Cloud Functions** exported from each codebase's entry module (`package.json` `main`,
  mapped back to `src/*.ts`), followed through `export * from`, `export { a } from`,
  `export * as group`, `exports.group = require()`, object groups (`export const admin = { ban }`
  deploys `admin-ban`), namespace members and `module.exports = { ... }`. Each is callable
  (`onCall`), HTTP (`onRequest`) or a trigger.

## Rules

| Rule | Tier | Meaning |
|---|---|---|
| `firebase-rules-public-write` | Fix | an update, delete or Storage write anyone can make, signed in or not. Create-only (contact forms, guest orders) is Review |
| `firebase-rules-open-catch-all` | Fix | `match /{document=**}` (or a Realtime Database root grant) open to anyone or any signed-in user |
| `firestore-self-writable-access-field` | Fix | rules read `get(...).data.<field>` to decide access, and a write the caller can pass without already holding that access leaves the field unconstrained: a user can set `role: "admin"` on their own document |
| `firestore-rule-unused` | Fix / Review | rules open the path to clients, but no client code uses it. Fix when any signed-in user or anyone can reach it, Review when a condition (an owner check) applies |
| `firebase-rules-signed-in-write` | Review | the only condition on a write is being signed in |
| `firebase-rules-public-read` | Review | readable without signing in: right for public content, a leak for personal data |
| `firestore-self-grantable-membership` | Review | `exists(.../admins/$(request.auth.uid))` grants access, and the create rule for that path only checks the uid |
| `firestore-path-without-rule` | Review | client code uses a path no rule allows: requests are denied (a functional break) |
| `uncalled-callable-function` | Review | an `onCall` function nothing in the app calls |
| `missing-callable-function` | Review | the app calls a function no codebase exports (removed, renamed, or deployed elsewhere) |
| `callable-without-auth-check` | Review | an `onCall` handler that never reads `request.auth` / `context.auth` and does not hand the request to a helper |
| `duplicate-cloud-function` | Info | Cloud Functions whose bodies are near-copies (85%+ after normalizing names and literals) |

HTTP (`onRequest`) functions are treated as external entry points (`autoEntryPoints`).

## Configuration

```json
{
  "platform": "firebase",
  "firebaseJson": "firebase.json",
  "wrappers": { "invoke": ["callFunction"], "firestore": ["docAt", "FirestoreDoc"] },
  "entryPoints": [{ "name": "adminOnlyTool", "reason": "called from the admin web app" }],
  "ignore": {
    "tables": [{ "name": "/config/client", "reason": "public client config by design" }],
    "edgeFunctions": [{ "name": "seedDemo", "reason": "run by hand from the console" }]
  }
}
```

- `platform`: `auto` (default) picks Firebase when `firebase.json` (or a root rules file)
  exists and no Supabase project does.
- `wrappers.firestore`: your own helpers whose string arguments are a Firestore path, or that
  take `{ collectionId: 'x' }`.
- `ignore.tables` takes rule paths as printed (`/users/{uid}`, `storage:/avatars/{f}`);
  `ignore.edgeFunctions` takes Cloud Function names.

## Limitations

- Rules are read from the repository. If you edit rules in the console, the deployed rules may
  differ; a live mode that compares them is on the [roadmap](../ROADMAP.md).
- Text-based extraction: a reference built in a way tracegrid does not follow (a generic
  repository class taking the collection name as a parameter) is listed as unresolved, and a
  "nothing uses it" finding that it could reach is downgraded to Review.
- Callers outside the repository (an admin web app, another mobile app) are invisible: declare
  them with `entryPoints` or ignore the finding with a reason.
- Old app versions in users' hands may still use paths and functions today's code does not.
  Check before closing a rule or deleting a function.
