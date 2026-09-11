# Prerecorded Case Playback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the existing Case UI from a live attack/repair controller into a stable prerecorded presentation player without changing its established header and visual language.

**Architecture:** Keep the existing CVE profiles and case-specific evidence components. Add a small deterministic playback reducer that exposes the current chapter, visible logs, patch progress, and before/after evidence. The page consumes this local presentation model and no longer exposes Bridge health, sudo, preflight, SSE, live repair, or environment reset controls.

**Tech Stack:** React 19, TypeScript, Vinext, CSS, Node test runner.

---

### Task 1: Playback state model

**Files:**
- Create: `app/presentation-state.mjs`
- Create: `tests/presentation-state.test.mjs`
- Modify: `tests/all.test.mjs`

- [ ] Write tests that require four ordered chapters, deterministic frame progression, pause/resume, restart, speed selection, and case switching.
- [ ] Run `node --test tests/presentation-state.test.mjs` and confirm it fails because the playback module does not exist.
- [ ] Implement the minimal pure reducer and derived presentation snapshot.
- [ ] Run `node --test tests/presentation-state.test.mjs` and confirm all playback tests pass.

### Task 2: Remove live-control UI and connect playback

**Files:**
- Modify: `app/page.tsx`
- Modify: `tests/case-state.test.mjs`

- [ ] Add source assertions requiring `开始演示`, `暂停`, `重新播放`, `演示数据已加载`, and the four presentation tabs.
- [ ] Add source assertions forbidding the sudo field, Bridge status panel, `运行 KINTSUGI`, Stage 0—10 progress, and a separate logs tab.
- [ ] Run `npm test` and confirm the new assertions fail against the current UI.
- [ ] Replace the header live controls with playback controls while preserving `workspace-header`, `global-bar`, `case-switcher`, `workspace-hero`, and `workspace-tabs`.
- [ ] Use the playback snapshot to drive evidence visibility, patch lines, result comparison, and synchronized logs.
- [ ] Keep the existing Ghostscript sample selector, but route it through prerecorded responses only.

### Task 3: Layout reduction and terminal dock

**Files:**
- Modify: `app/globals.css`
- Modify: `tests/case-state.test.mjs`

- [ ] Add style assertions for the playback status, compact controls, four-chapter overview, terminal dock, and responsive reflow.
- [ ] Run `npm test` and confirm the style assertions fail.
- [ ] Remove unused Bridge/pipeline layout rules from the active page and add the playback components using existing colors, borders, spacing, and breakpoints.
- [ ] Run `npm test` and confirm the source and style assertions pass.

### Task 4: Verification

**Files:**
- Verify only; no new production files expected.

- [ ] Run `npm test` and confirm zero failures.
- [ ] Run `npm run lint` and confirm zero lint errors.
- [ ] Run `npm run build` and confirm a successful production build.
- [ ] Inspect the running UI at desktop and compressed widths, confirm the original header form remains recognizable, all four tabs are reachable, playback can pause/restart, and no horizontal overflow or narrow three-column console failure remains.
