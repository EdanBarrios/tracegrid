# Output

It prints which Supabase project and code roots it used, then the top findings with `file:line`. Full output goes to `./tracegrid-out/`.

If it warns about **0 code files, 0 Supabase call sites or 0 migrations, the result is empty,
not clean**: set `include` or `supabaseDir` in `tracegrid.config.json` (with `--check` such a
run exits 2).

| File | What |
|---|---|
| `report.md` | Findings with `file:line`, suppressions with their reasons, and everything it could not resolve, parse or apply |
| `graph.json` | `schema_version` 1. networkx node-link graph (`nodes`, `links` with `relation` and `confidence`: `extracted`, `inferred` or `ambiguous`), plus `rules`, `findings`, `suppressed`, `stats`, `project`, `warnings` |
| `graph.html` | One self-contained page that works offline. Findings sidebar grouped Fix / Review / Info with search and filters; a **dashboard** (exposure score, a role × surface reach matrix, the biggest holes drawn as one-line paths, findings by rule, top folders by database touchpoints, tables that rely on Supabase's legacy default grants, and scan coverage); a **path view** that shows a selected finding's neighbourhood in columns (Code, Entry points, Database, Roles), including "no caller in code"; a **full map** with folders and schema+kind groups collapsed until clicked; and an optional **3D** showcase. |

The 3D view is the only thing that touches the network: on click it loads one pinned library,
`3d-force-graph@1.80.1` from jsDelivr, with a Subresource Integrity hash and
`crossorigin="anonymous"`. Nothing else is fetched and no data leaves the page. Offline, it
says so and the 2D views keep working. Deep links: `graph.html#f=<fingerprint>` (or `f=first`)
selects a finding and opens its path, `view=dash`, `view=path`, `view=map` or `view=3d` opens that view. Every colour, stroke, radius and font is a CSS variable in the THEME block at the top of the page's stylesheet.

## Colourways

`graph.html` ships five colourways, each with a dark and a light variant: `signal` (the
default: red and amber), `ember` (the default for Firebase projects: the same black and grid in
orange and yellow), `graphite-amber` (soft gold and slate), `mono` and `mint`. Severity is never colour alone:
the glyphs ◆ Fix, ◇ Review and · Info always go with it. Pick one in the page (gear button in the
sidebar: colourway, light / dark / auto, auto-rotate for the 3D tab; saved in the browser's
localStorage), with `?colorway=mono` on the URL (beats the saved choice), or set the default baked
into the file with `"colorway": "mint"` in `tracegrid.config.json` or `--colorway mint` (the flag wins).
Unknown names fail with the list of valid ones. The palettes are the THEME block at the top of
`src/html.js`.

[Back to docs](README.md)
