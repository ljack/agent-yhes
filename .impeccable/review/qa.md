# Tutorial QA

Current captures: desktop.png is 1440 CSS px, light; mobile.png is 390 CSS px, dark; both DPR 2, full-page from top. Captured with Chrome DevTools UI through CUA because browser host/IAB unavailable. Both inspected after saving. No approved comp; user specified two terminal/person lanes and clean progressive explanation.

Observed through native Chrome CUA: chapter selection, Next/Back, Play/Pause, custom long send, invalid command error and playback stop, LLM object drawer + Escape, Why expansion pausing playback, human example gate, cancellation and retry, theme keyboard operation, Get started and responsive 390 layout. Broker paused case reached Git catch-up and recipient message. Source patch removed stale cancellation line after a retry, keeps broker-offline state scoped to Message, and updates Crypto captions for reverse direction. Model tests (8) cover review gate, exact words, ordering, outage, reverse direction, replay bounds and data-only parsing. Latest browser console empty.

Mechanical detector ran once: cramped packet inset, functional text <11px, body microtext and colored shadow. Fixed the noted inset, increased labels, and neutralized elevation shadow; no second detector run. No backend, network API, model, shell, real signing, or biometric work occurs from this page.

Finish-review correction: a compact playback bar now appears at widths <=780px
when the main step narration leaves the viewport. `mobile-bob.png` shows Bob's
terminal with the current step title/count and playback controls at 390x844.
Next advanced 1/6 to 2/6 from that bar in Chrome. It shares the main controls'
handlers and approval gate, and extra bottom padding keeps final content clear.
The desktop layout is unchanged. The scoped quality bar and workflow exception
are recorded in ../surfaces/tutorial-quality.md.

## Remediation pass (`ay-15up`)

Verified with headless Playwright Chromium (`1440×900` light/dark and `390×844` light/dark, including `prefers-reduced-motion: reduce`), `node --test tests/test_tutorial.cjs` (13 passing, including guarding-copy check), `python3 -m unittest discover -s tests -p test_site.py -v` (3 passing), and `python3 tools/build_site.py`:
- Actor-aware `Catch up` / `inbox` and `Connect` flows, synced command prefills, Replay custom-text retention, online listener vs offline manual `$ inbox` separation, and explicit rejection of unsupported `listen`/`flush`/`connect` shortcuts.
- Inline two-column desktop inspector (zero overlap with playback or diagram; stays readable across `Next step`) and bottom-sheet mobile inspector positioned above `#mobile-playback`, with `aria-expanded`/`aria-controls` and Escape/Close focus return.
- Corridor-routed SVG connectors checked programmatically across every step of all 4 chapters (both Alice and Bob, online and offline) on desktop and mobile with zero short/zero-length arrows and zero hidden behind-card intersections.
- Chapter-scoped broker pause state (`#broker-toggle` hidden outside `Message` and non-overlapping with `.shared-note` on mobile), unified `public-key fingerprint` and `Alice’s agent, Bob’s agent` wording, `BOOTSTRAP.md#prepare-a-pair-once` anchor preservation in `dist/site`, expandable CLI mapping table, `>= 24×24px` interactive target bounds, and automatic hiding of `#mobile-playback` while viewing `#getting-started`.
- No real physical iPhone or two-Mac/GHES live session was executed in this pass.
