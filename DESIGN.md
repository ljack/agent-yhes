---
name: "agent-yhes educational tutorial"
description: "A restrained interactive diagram of authorship and transport."
colors:
  bg: "#f4f7f8"
  surface: "#fff"
  soft: "#eaf0f2"
  ink: "#192b34"
  muted: "#56666e"
  line: "#ced9dd"
  accent: "#14665c"
  accent-text: "#fff"
  alice: "#4354a2"
  alice-soft: "#edf0fc"
  bob: "#116e60"
  bob-soft: "#e6f4ef"
  terminal: "#17252e"
  terminal-text: "#e2eaf0"
  terminal-muted: "#a8bac5"
  terminal-line: "#3b4a54"
  focus: "#267bc5"
  warning: "#8a540d"
  warning-soft: "#fff2db"
  route: "#526985"
  bg-dark: "#111c23"
  surface-dark: "#1b2a33"
  soft-dark: "#243640"
  ink-dark: "#edf3f5"
  muted-dark: "#b2c0c8"
  line-dark: "#425863"
  accent-dark: "#81d2be"
  accent-text-dark: "#102a25"
  alice-dark: "#b3bfff"
  alice-soft-dark: "#2e395b"
  bob-dark: "#8bd8c4"
  bob-soft-dark: "#193e36"
  terminal-dark: "#0d171d"
  focus-dark: "#92caff"
  warning-dark: "#f3ca8c"
  warning-soft-dark: "#43351f"
  route-dark: "#a8bdd8"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "27px"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "19px"
    fontWeight: 650
    lineHeight: 1.35
    letterSpacing: "-0.015em"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "15px"
    lineHeight: 1.5
  prose:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "13px"
    lineHeight: 1.5
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.25
  code:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "12px"
    lineHeight: 1.7
rounded:
  control: "6px"
  field: "5px"
  panel: "9px"
  dialog: "12px"
spacing:
  compact: "4px"
  control-gap: "8px"
  inset: "12px"
  section: "16px"
  panel: "20px"
  group: "24px"
  wide: "32px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-text}"
    rounded: "{rounded.control}"
    padding: "8px 14px"
  button-outlined:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 14px"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 14px"
  button-run:
    backgroundColor: "#b0decf"
    textColor: "#152a25"
    rounded: "4px"
    padding: "7px 10px"
  command-field:
    backgroundColor: "#0f1b23"
    textColor: "{colors.terminal-text}"
    rounded: "{rounded.field}"
    padding: "3px 4px 3px 10px"
  chapter-current:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bg}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  local-node:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "7px 3px"
  shared-service:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "15px 9px"
---

# Design System: agent-yhes educational tutorial

## Overview

**Creative North Star: "Authorship and transport, visible"**

This record covers only the educational HTML tutorial in tutorial/. It does not set design policy for the protocol, CLI or native macOS signer. It describes the finished source implementation, not browser-computed measurements.

A cool workspace supports dark terminals and named local actors. Restrained app typography, stable actor colors and fine boundaries keep one operation legible at a time. Optional explanations preserve a compact first view. The north star is a descriptive summary of the supplied direction, not a separately selected brand concept.

**Key Characteristics:**

- Cool neutral workspace with dark terminals.
- Persistent indigo Alice and teal Bob identities.
- Stable actor geometry with one current route.
- Progressive disclosure and synchronized mobile playback.

## Colors

The frontmatter preserves CSS color notation. Unsuffixed values represent light mode; `-dark` entries record changed dark-mode values. The terminal text, secondary terminal text and terminal dividers remain unchanged between themes. The explicit theme control saves its preference locally where storage is available; its fallback is light.

### Primary

- **Action teal** (`accent`, `accent-text`): primary controls, links, progress and travelling packet.
- **Bob teal** (`bob`, `bob-soft`): Bob’s identity and local active states.

### Secondary

- **Alice indigo** (`alice`, `alice-soft`): Alice’s identity and local active states.
- **Focus blue** (`focus`): keyboard outlines.
- **Warning amber** (`warning`, `warning-soft`): broker pause, paired with a dashed border and written status.

### Neutral

- **Cool workspace** (`bg`, `surface`, `soft`): page, containers and quiet groupings.
- **Ink and structure** (`ink`, `muted`, `line`): text hierarchy and boundaries.
- **Terminal slate** (`terminal`, `terminal-text`, `terminal-muted`, `terminal-line`): code surface and readable records.
- **Route slate** (`route`): current diagram connections; notification routes use action teal.

**The Actor Identity Rule.** Keep Alice indigo and Bob teal, with names and positions providing redundant identity cues.

## Typography

The system sans stack supplies compact app headings and explanations; there is no separate display identity. Monospace identifies actual command and packet content. The frontmatter captures the reused roles, not a mathematical scale.

The page headline becomes (24px) on mobile. Current-step titles become (18px) at the compact breakpoint. Setup and approval headings use (25px); person names use (17px). Explanatory paragraphs use the prose role, with narration limited to (72ch), Why to (76ch), and inspector text to (65ch). Supporting annotations use (11–12px), a dense-label treatment rather than a default for new paragraphs. The setup prompt uses (13px) monospace, then (12px) on mobile. Step counts use tabular numerals.

**The Literal Code Rule.** Reserve monospace for commands, terminal records and sealed packet labels.

## Layout

The masthead, main content and footer share a centered (1440px) maximum width and (32px) horizontal padding. Chapter navigation and narration precede the diagram. The desktop diagram has equal flexible person lanes around a (190px) shared column, separated by (38px) gaps. Local tool groups use three equal columns. These are tutorial composition measurements, not a template for unrelated screens.

At widths of at least (1450px), the shared column becomes (210px) and gaps (48px). At widths up to (1080px), page padding becomes (20px), the shared column (150px), and diagram gaps (20px). At widths up to (780px), page padding becomes (16px), actors stack in Alice/shared/Bob reading order, shared services sit side by side, chapters form two columns, and narration and setup steps become single-column.

Terminal output scrolls within a stable region (118px normally, 122px wide and 120px mobile). Actor headings reserve a (16px) bottom margin ((14px) mobile), local tool rows use (14px) gaps ((10px) compact, (12px) mobile) and (18px) vertical row corridors ((16px) mobile), and `.world` preserves horizontal gutter padding (`18px` desktop, `14px` compact/mobile) for edge routes. On mobile, a fixed compact playback bar appears only when narration is outside the viewport and `#getting-started` is not open in view (`body.has-mobile-bar`). It mirrors the step count with active-actor cue, title and Back/Play/Next actions, with (42px) minimum button height, (12px) side offsets and a (10px) bottom offset. Body bottom padding is (112px). On mobile, the inspector becomes a bottom panel with (12px) edge offsets (`bottom: 114px` and `max-height: min(46dvh, calc(100dvh - 130px))` when the mobile playback bar is visible; `bottom: 12px` and `max-height: min(42dvh, calc(100dvh - 460px))` otherwise).

## Elevation & Depth

The workspace uses tonal separation and fine borders. Active local nodes and services add a (1px) inset colored stroke to communicate state, not elevation. The inspector adds a (3px) accent left border and ambient shadow: `0 12px 42px rgba(0,0,0,.16)` in light mode and `0 12px 42px rgba(0,0,0,.35)` in dark mode. Approval uses a native dialog with a dim backdrop.

**The Flat Workspace Rule.** Use borders and tonal surfaces for diagram structure; reserve the ambient shadow for the inspector panel.

## Shapes

Control, field, panel and dialog radii are recorded in the frontmatter. The inspector uses (9px) corners on desktop, (10px) on mobile, and mobile playback uses (8px). Human avatars are (36px) circles with identity initials. Structural borders are generally (1px); terminals reserve a (2px) border for current-operation color.

The diagram’s authored SVG icons use rounded caps and joins, generally (24px) with (1.6px) strokes; local-node icons are (21px). Route strokes are (2.1px) at (.86) opacity ((.68) on mobile), with (5px/5px) dashes for reasoning and notification, routed through explicit row/column corridors and outer gutters so lines stay clear of cards. Other route segments are solid. This is explanatory geometry. The favicon is inline SVG. No raster assets ship; screenshots under `.impeccable/review/` are review evidence only.

## Components

### Buttons

Primary, outlined and quiet buttons share a (40px) minimum height and the control shape. Primary uses action teal, outlined uses surface and divider colors, and quiet rests transparent. Outlined and quiet hover into the soft surface; primary hover uses brightness (.93). State transitions last (.16s) with `ease`. Focus is a (3px) outline offset (4px); disabled opacity is (.42). Guide options reuse outlined buttons with accent selection and `aria-pressed`. The smaller terminal Run button uses a pale green fill, dark text and (30px) minimum height ((34px) on narrow or coarse-pointer screens); terminal shortcut fill buttons maintain at least (26px) height/width ((32px) height on narrow/coarse-pointer screens), and standalone footer/guide links use (28px) minimum height.

### Inputs / Fields

Terminal inputs sit in a dark outlined row with prompt and Run action. Input text is monospace, transparent and borderless; its keyboard outline has a (1px) offset and its caret is pale blue. Inline status explains invalid input. Help buttons fill the field and return focus. The HTML limit is (280 characters); message text is limited to (240 characters). Commands animate the walkthrough; both terminals stay synced with the active story and preserve custom input on Replay.

### Navigation

Four numbered chapters expose meaningful sequence. The current chapter uses ink fill, page-background text and `aria-current="step"`. Hover uses soft fill and ink text. Chapter changes reset the example, clear temporary feedback and collapse Why. The same order survives the mobile grid.

### Actors and services

Local nodes combine authored SVG, a name and supporting role. Their hover and selected states use the owner’s pale fill and border. Active state adds an inset stroke and stronger icon and name color. Each inspectable button exposes `aria-expanded` and `aria-controls="inspector"`. Shared services are neutral at rest, accented when active, and amber with dashed outline when the broker is paused or unavailable; the broker pause toggle is shown only in the Message chapter. Inspection pauses playback and focuses Close; toggling the open object, Close, or Escape closes it and returns focus (scrolling into view if needed) to the original node.

### Terminals

Dark terminal panels retain identity in both themes. Wrapped records accumulate above the command row, with an active border marking the current operation. Human-original records carry an explicit text prefix. Terminal logs do not announce every accumulated line; narration has a separate polite status announcement.

### Narration and playback

The current step combines a tabular counter, heading, short explanation and packet status. Why is initially collapsed; opening it pauses playback. Sealed packets use monospace and action color. A (3px) segmented lower edge shows progress. Replay, Back, Play/Pause and Next share the same state as compact mobile playback.

Autoplay advances every (3100ms), stopping at chapter completion or the human-review gate. One travelling dot follows the current route for (900–2300ms), based on path length. Reduced-motion preference removes transitions and the dot animation, preserving the static route and written state.

### Inspector and approval

On desktop, the nonmodal inspector docks inline between narration and the diagram as a two-column (`1.35fr` / `1fr`) panel so readers can inspect an object while stepping through playback; on mobile it sits above the compact playback bar (or bottom edge when hidden). The modal approval dialog preserves exact words, author and agent recipients (`Alice’s agent, Bob’s agent`), focuses Cancel first, contains backdrop scroll, and restores focus to its opener. Cancellation preserves the review gate; approval advances the flow.

### Getting started

An explicit reveal control opens setup. Two outlined options choose simulation or two-person instructions, with a fragment-preserving link to `BOOTSTRAP.md#prepare-a-pair-once` and an expandable shortcut-to-CLI reference table (`details.cli-map`). Ordered steps remain plain content. A tonal monospace block holds the copyable prompt; clipboard failure selects the prompt for manual copying and announces the fallback.

## Do's and Don'ts

### Do:

- **Do** preserve actor names, positions and colors across steps.
- **Do** synchronize narration, packet state and playback controls.
- **Do** retain optional Why text and object inspection.
- **Do** use authored inline SVG for the diagram icon system.
- **Do** retain theme-aware keyboard focus and reduced-motion behavior.

### Don't:

- **Don't** extend this tutorial record into protocol, CLI or native signer design policy.
- **Don't** use color alone for identity or state.
- **Don't** imply illustrative commands execute real operations.
- **Don't** treat review screenshots as shipped imagery.
