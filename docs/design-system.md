# Magen Design System

**Theme statement:** *Precise, calm, trustworthy shield.* Magen (Hebrew: "shield") should feel like a quiet, competent instrument — never alarmist, never decorative. Findings are the product; the UI exists to make evidence legible and decisions easy.

**Dials:** balanced creativity · default density (compact available) · dark-first, light supported · desktop-first (Electron, min window 1024×680).
**Style family:** restrained "instrument panel" — flat surfaces, hairline borders, minimal shadow, one brand hue, color used only for meaning.
**Avoid:** neon "hacker" green-on-black, gradient hero blocks, glassmorphism, skull/lock clichés, red used for decoration, purple gradients.

Tokens live in `frontend/src/styles/tokens.css`; Tailwind maps them in `frontend/tailwind.preset.ts`. Values here mirror those files — if they disagree, **the CSS wins**; fix this doc.

**Theme "system":** tokens.css defines palettes only for `data-theme="dark"` and `"light"`. The app's `ThemeProvider` resolves a "system" preference to one of those two before writing `data-theme`, so never set `data-theme="system"` directly.

---

## 1. Principles

1. **Evidence first.** Every finding screen leads with what was found and where, then why it matters, then the fix.
2. **Color is never the only signal.** Severity and status always pair color with an icon and a text label (colorblind-safe, screenshot-safe in a thesis).
3. **Honest about certainty.** Confirmed / Potential / Inconclusive and Static / Runtime / AI are visually distinct everywhere. AI text is always marked.
4. **Calm by default.** Only Critical/High use warm color at full strength. No flashing, no alarm animation.
5. **Tokens, not values.** Components consume semantic tokens only (`bg-surface`, `text-fg-muted`, `p-4`). No hex, no arbitrary pixel values.
6. **Safe by design.** Destructive or network-touching actions are explicit, confirmed, and cancellable.

## 2. Color

OKLCH is preferred for authoring; hex shipped. Contrast was computed (WCAG 2.x) for every text/UI pairing below.

### Neutral scale (cool, slight blue tint)
| Token | Hex | Token | Hex |
|---|---|---|---|
| neutral-50 | `#F6F8FA` | neutral-600 | `#525C6D` |
| neutral-100 | `#EDF0F4` | neutral-700 | `#3B4352` |
| neutral-200 | `#DFE3EA` | neutral-800 | `#272D39` |
| neutral-300 | `#C6CCD6` | neutral-900 | `#181C25` |
| neutral-400 | `#9AA3B2` | neutral-950 | `#0F1219` |
| neutral-500 | `#6F7A8C` | | |

### Brand scale (steel teal)
| 100 | 200 | 300 | 400 | 500 | 600 | 700 | 800 | 900 |
|---|---|---|---|---|---|---|---|---|
| `#D6F4F1` | `#A9E8E2` | `#6FD6CE` | `#38BDB4` | `#1FA39B` | `#168781` | `#126B67` | `#0F5250` | `#0B3B3A` |

Brand color is for primary actions, focus, selection, and the logo only. **Never** use it for severity, body text, or error states.

### Semantic roles (dark / light)
| Role | Dark | Light |
|---|---|---|
| bg | neutral-950 | neutral-50 |
| surface | neutral-900 | #FFFFFF |
| surface-raised | neutral-800 | #FFFFFF |
| border | neutral-700 | neutral-200 |
| border-strong | neutral-500 | neutral-500 |
| text | #E8ECF2 | neutral-900 |
| text-muted | neutral-400 | neutral-600 |
| primary (button bg) | brand-500 | brand-700 |
| on-primary | neutral-950 | #FFFFFF |
| focus ring | brand-400 | brand-600 |

### Severity (paired with icon + label)
| Severity | Dark | Light | Icon (lucide) |
|---|---|---|---|
| Critical | `#FF6B6F` | `#C62A2F` | `octagon-alert` |
| High | `#FF9A52` | `#B84A00` | `triangle-alert` |
| Medium | `#F0B429` | `#8A5B00` | `circle-alert` |
| Low | `#6AA6FF` | `#1D5FD1` | `info` |
| Info | neutral-400 | neutral-600 | `circle-dot` |

Each has a `-bg` tint (14% alpha in dark; pale solid in light) for badges and row highlights.

### Verified contrast (WCAG 2.x)
| Pair | Ratio | Requirement |
|---|---|---|
| Dark text on bg | 15.8 | ≥ 4.5 ✔ |
| Dark muted text on surface | 6.7 | ≥ 4.5 ✔ |
| Dark severity text on surface | 6.2–9.2 | ≥ 4.5 ✔ |
| Dark brand-400 on bg | 8.1 | ≥ 4.5 ✔ |
| Dark primary button (ink on brand-500) | 6.0 | ≥ 4.5 ✔ |
| Dark border-strong on bg / surface | 4.3 / 3.9 | ≥ 3 (UI) ✔ |
| Light text on white | 17.1 | ≥ 4.5 ✔ |
| Light muted text on white | 6.8 | ≥ 4.5 ✔ |
| Light severity text on white | 5.2–5.9 | ≥ 4.5 ✔ |
| Light primary button (white on brand-700) | 6.3 | ≥ 4.5 ✔ |
| Light border-strong on white | 4.3 | ≥ 3 (UI) ✔ |

*Re-run contrast checks whenever a token changes: `python scripts/check_contrast.py` (runs in CI; parses tokens.css, composites translucent tints, checks every pairing including severity badges on their `-bg` tints). Tightest current margins: light-theme High badge 4.69, Critical badge 4.87.*

### Finding status & source (not color-only)
| Concept | Treatment |
|---|---|
| **Confirmed** | Solid filled badge, check-circle icon |
| **Potential** | Outlined badge, help-circle icon |
| **Inconclusive** | Dashed-outline badge, minus-circle icon |
| **Static** evidence | `file-code` icon tag |
| **Runtime** evidence | `radio` icon tag |
| **AI-generated** | `sparkles` icon + `ai` tint panel + "AI-generated — review before use" caption |
| **Validated fix** | `shield-check` icon + "Validated" label; unvalidated shows `shield-question` + "Not validated" |

AI purple (`--color-ai`) is used **only** to mark AI-generated content, so users can always tell machine prose from deterministic findings.

## 3. Typography

**Fonts (bundled locally — the app must work offline):** `@fontsource-variable/inter` (UI) and `@fontsource-variable/jetbrains-mono` (code, evidence, HTTP, config). Fallbacks defined in tokens.

**Scale** — product UI, ratio ≈ 1.125–1.2, base 14px (dense desktop; deliberate deviation from 16px).

| Token | Size | Role | Weight | Line-height | Tracking |
|---|---|---|---|---|---|
| text-xs | 11px | caption, badge | 500 | 1.4 | +0.02em |
| text-sm | 12px | label, table header | 500 | 1.4 | +0.01em |
| text-base | 14px | body, table cell | 400 | 1.5 | 0 |
| text-md | 16px | emphasized body | 400/500 | 1.5 | 0 |
| text-lg | 18px | heading-sm | 600 | 1.25 | 0 |
| text-xl | 22px | heading-md (page title) | 600 | 1.25 | −0.01em |
| text-2xl | 28px | heading-lg (dashboard stat) | 600 | 1.25 | −0.01em |

Code/evidence: `font-mono`, 13px (`text-sm`+), line-height 1.6, `tabular-nums` for numbers, never wrap by default (horizontal scroll with copy button). Truncate long paths/URLs in the middle with a tooltip showing the full value.

## 4. Spacing, layout, shape, depth

- **Base unit 4px.** Scale: 4, 8, 12, 16, 20, 24, 32, 48, 64 (`space-1…16`).
- **Layout:** fixed left sidebar (232px, collapses to 56px) + main content (max 1280px). Master–detail for Findings (list left, detail right; stacked below 1100px — Tailwind `split:` screen in the preset).
- **Breakpoints (window width):** 1024 min · 1280 comfortable · 1600 wide. Not mobile — Electron desktop.
- **Density:** compact (row 28px), default (36px), comfortable (44px). Set in Settings; stored per user.
- **Radius:** sm 4 (badges, inputs inner), md 8 (buttons, inputs, cards), lg 12 (dialogs). One radius family per component — never mix.
- **Depth:** hairline borders carry structure; shadow only for floating layers (menu/popover `shadow-2`, dialog `shadow-3`). Cards are flat (`border` + `surface`).
- **Minimum target size:** 32px height for interactive controls.

## 5. Motion

| Use | Duration | Easing |
|---|---|---|
| Hover/press/color | 120ms | standard |
| Panel, menu, tab | 200ms | standard (enter) / exit |
| Dialog, drawer, page transition | 320ms | standard |
| Scan progress | determinate bar; no spinner loops > 10s without text status | — |

`prefers-reduced-motion` zeroes durations. No bounce, no parallax, no attention-seeking pulses; progress is shown with text ("Probing 12/40 endpoints").

## 6. Iconography

`lucide-react` only, 16px inline / 20px nav, 1.5 stroke, `currentColor`. Every icon-only button has an `aria-label` and tooltip. No custom icon unless the logo.

## 7. Logo

Shield mark (rounded shield, negative-space check or API bracket `{ }`) in brand-500; wordmark "Magen" in Inter 600. Clear space = height of the "M". Minimum size 16px mark / 72px lockup. Mono (currentColor) variant for dark/light and exports.

## 8. Components

Built on shadcn/ui primitives, restyled via tokens. Prefer composing shadcn; add a component here before building a new one.

| Component | Variants / states | Notes |
|---|---|---|
| **Button** | primary, secondary, ghost, danger; sm/md; default, hover, active, focus, disabled, loading | Loading keeps width, shows spinner + text. Danger needs confirm dialog. |
| **Input / Textarea / Select** | default, focus, error, disabled, read-only | Label always visible above; helper + error text below (`aria-describedby`). |
| **SeverityBadge** | critical/high/medium/low/info | Icon + label + tint bg. Never color-only. |
| **StatusBadge** | confirmed/potential/inconclusive | Solid / outline / dashed. |
| **SourceTag** | static/runtime/correlated | Icon + label. |
| **AiPanel** | collapsed, loading, ready, unavailable, error | `ai` tint, sparkles icon, caption, regenerate, "copy". Unavailable → shows deterministic template explanation + "Start Ollama" hint. |
| **FindingRow** | default, hover, selected, resolved (retest) | Columns: severity, title, rule id, location, status, source. |
| **FindingTable** | sortable, filterable, empty, loading (skeleton), error | Implemented as `FindingList`: a `listbox` with roving focus (↑/↓/Home/End, selection follows focus). Rows use `content-visibility: auto` so 10 000 rows stay cheap without a virtualization dependency. Filters persist in the URL (`?sev=&status=&source=&f=`). |
| **EvidenceBlock** | code, request/response, config excerpt | Mono, line numbers, highlighted lines, copy, redacted tokens shown as `••••`. |
| **DiffView** | unified / split | `diff-add` / `diff-del` tints + `+`/`−` gutter glyphs (not color-only). |
| **FixCard** | template fix, AI fix; validated / not validated | Export & copy actions; never an "Apply to file" button (Option B). |
| **ScanProgress** | idle, running, cancelling, done, failed | Always a visible Stop button. |
| **TargetAllowlistForm** | host input, authorization checkbox, confirm | Records timestamp; clear warning copy (see §10). |
| **CompareView** | resolved / persists / new | Three-column summary with counts. |
| **EmptyState** | per page | Icon, one-line explanation, single primary action. |
| **Skeleton** | block (any size) | `aria-hidden`; parent provides `aria-live` status text. Pulse disabled under reduced motion. |
| **CopyButton** | idle, copied | Ghost icon button; `aria-label` switches to "Copied". Used by EvidenceBlock, AiPanel, FixCard. |
| **Logo** | mark | Shield + check, `currentColor`, `aria-hidden` (wordmark carries the name). |
| **BackendStatus** | checking, ok, error | Sidebar footer; icon + text, `role=status` polite live region; shows version + commit. |
| **FileField** | empty, selected, error, disabled | Labelled file picker (`<input type=file>` visually styled); shows file name + size, clear button (`aria-label`), helper/error text. Reads the file locally; nothing is uploaded anywhere but the loopback backend. |
| **SummaryStrip** | default, empty | Counts per severity (SeverityBadge + tabular number) and per status (StatusBadge + number). Text-only counts, never color-only. |
| **FilterBar** | none active, some active | Toggle chips (`aria-pressed`) for severity, status, source; icon + label; "Clear filters" ghost button. |
| **Alert** | info, warning, danger | Feedback tint + icon + text; `role=alert` for errors, `role=status` otherwise; optional action (e.g. Retry). Used for partial / failed scans and coverage notes (unresolved includes). |
| **Toast / Alert / Dialog / Tooltip / Tabs / Sidebar** | shadcn defaults, token-styled | Alerts use feedback colors + icons. |

## 9. Screens (page tree, in reading order)

1. **Targets** — header + "Add target"; list of targets (host, last scan, status); EmptyState.
2. **New Scan** — target select → inputs (OpenAPI file, Nginx file, base URL, optional auth header) → scan options (rate limit, request cap) → Start.
3. **Scan Progress** — stage stepper (Static → Runtime → Correlate → AI), live counts, Stop.
4. **Findings** — summary strip (counts by severity/status) → filter bar → master list | detail.
5. **Finding Detail** — title + severity/status/source badges → Evidence → Why it matters → Fix (template / AI, diff, validation state) → References (OWASP/CWE) → Mark reviewed.
6. **Retest / Compare** — pick baseline scan → run → CompareView.
7. **Settings** — theme, density, Ollama (URL, model, status, test), allowlist, data export/delete.

## 10. Content & tone

- Plain, specific, calm. "CORS allows any origin on `/v1/users`" not "Dangerous CORS misconfiguration detected!!"
- Verbs on buttons: "Start scan", "Export fix", "Retest". Sentence case everywhere.
- Authorization copy (shown before any runtime scan): *"Only scan systems you own or have written permission to test. Magen sends safe, rate-limited requests to the host you add."*
- Empty/error states say what happened, why, and the next action.
- Numbers: tabular figures, locale formatting; dates ISO-ish with relative tooltip.

## 11. Accessibility (WCAG 2.1 AA target)

- Contrast verified (§2); focus ring 2px + 2px offset on all interactive elements, never removed.
- Full keyboard operation: Tab order follows reading order; table rows arrow-navigable; Esc closes layers; focus trapped in dialogs and returned on close.
- Roles/labels: icon buttons labelled; badges expose text; live region (`aria-live="polite"`) for scan progress and toasts; tables use proper `th scope`.
- Not color-only (severity, status, diff). Respect `prefers-reduced-motion` and `prefers-color-scheme`.
- Text resizable to 200% without loss; layout reflows at min window width.

## 12. States checklist (every data view)

Default · loading (skeleton) · empty · error (with retry) · partial (some probes failed) · offline/Ollama-unavailable · long text (truncate with tooltip) · 1 vs 10,000 findings · RTL/long-string tolerance.

## 13. Handoff tokens summary

| Token | Value | Usage |
|---|---|---|
| `color-primary` | brand-500 (dark) / brand-700 (light) | Primary buttons, selection |
| `color-focus` | brand-400 / brand-600 | Focus ring |
| `color-border` | neutral-700 / neutral-200 | Card/table borders |
| `space-4` | 16px | Card padding, section gap |
| `radius-md` | 8px | Buttons, inputs, cards |
| `text-base` | 14px / 1.5 | Body, table cells |
| `font-mono` | JetBrains Mono | Evidence, diffs, config |
| `duration-base` | 200ms | Panels, menus |

## 14. Governance

- New component or token → add here first (name, variants, states, a11y), then implement.
- `node scripts/lint-hex.mjs` (part of `npm run lint`, runs in CI) fails on hex colors outside tokens.css, Tailwind arbitrary values (`p-[13px]`, `bg-[#...]`) and default-palette classes (`bg-red-500`, `text-white`). The preset *extends* Tailwind's theme, so those still compile and must be caught by lint.
- A Storybook (or `/dev/components` route) renders every component × state × theme × density for visual review and screenshots for the thesis.
- Visual changes that alter tokens bump the design-system version in this file's header and are noted in `CHANGELOG.md`.

*Design system version: 0.2.0*
