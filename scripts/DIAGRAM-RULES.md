# Diagram rules

Rules for every branded diagram built by `scripts/build-diagrams.mjs`. Run `node scripts/build-diagrams.mjs` after any change. It exits non-zero when a label or callout cannot be placed without overlap.

## Look

- Dark isometric plate, grain, teal, purple and lime glows, theAuth mark top left, `theauth.dev` top right.
- Colors come from the `C` palette only. Teal is a normal flow, lime is the main path or data, purple is theAuth, red is something refused.
- Every block gets an icon from `ICONS`. Add a new icon there instead of drawing one inline.
- Routes are lifted pipes with a shadow, stems and a flowing dash. Motion is disabled under `prefers-reduced-motion`.

## Layout

- Nodes sit on the 10 by 10 plate. Chains run along the anti-diagonal so they read left to right.
- Six nodes at most, four callouts at most. If it needs more, split it into two diagrams.
- Node labels are pills above the block, or below for lower nodes. Callouts are numbered bubbles inside the scene, never in the caption.
- Nothing may overlap a node, another label or a group label. Labels never sit on a route. The build fails on overlap.

## Text

- Pill labels are 26 characters or fewer. Callouts are two lines of 24 characters or fewer.
- The caption line is one or two sentences, 110 characters or fewer, and says what the picture shows.
- No em dashes or en dashes anywhere. Sentence case.

## Standalone and search

- Every SVG carries `<title>`, `<desc>`, the title and the one line explanation, so it works on its own.
- File names are descriptive: `theauth-<topic>.svg`. Put them in `docs/images/diagrams` or a topic folder.
- Embed with a `<Frame caption>` and an `alt` that matches the `<desc>`.
- Keep SVG as the source. Export PNG only for social cards, since the grain makes PNGs heavy.
