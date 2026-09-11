# KINTSUGI Case UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将已认可的 KINTSUGI 演示界面定稿为 Case UI，并为三个 CVE 提供清晰、贴合漏洞机制的专属证据展示。

**Architecture:** 保留现有单页前端状态机，将案例静态资料集中在 `app/case-state.mjs`。页面组件根据统一的案例证据接口渲染命令执行链、恶意文件链或网络访问链；攻击、修补、复测仍使用同一套可测试的状态转换。

**Tech Stack:** Vinext、React、TypeScript、CSS、Node.js test runner、ESLint。

---

### Task 1: Rename the isolated UI

**Files:**
- Rename: `Kintsugi_CVE_Demo_UI` → `Kintsugi_CVE_Case_UI`
- Modify: `Kintsugi_CVE_Case_UI/package.json`
- Modify: `Kintsugi_CVE_Case_UI/README.md`
- Modify: `Kintsugi_CVE_Case_UI/app/layout.tsx`

- [ ] Rename the folder after confirming the destination does not exist.
- [ ] Replace product-facing “Demo” naming with “Case”.
- [ ] Confirm Git reports only the new Case UI folder.

### Task 2: Define case-specific evidence with TDD

**Files:**
- Modify: `Kintsugi_CVE_Case_UI/tests/demo-state.test.mjs`
- Rename: `Kintsugi_CVE_Case_UI/tests/demo-state.test.mjs` → `tests/case-state.test.mjs`
- Rename: `Kintsugi_CVE_Case_UI/app/demo-state.mjs` → `app/case-state.mjs`

- [ ] Add failing assertions for each profile's `story`, `request`, `evidenceView`, and `metrics` fields.
- [ ] Run `npm test` and verify the new assertions fail because fields are absent.
- [ ] Add the minimum profile data needed for the three evidence views.
- [ ] Run `npm test` and verify all tests pass.

### Task 3: Render three distinct cases

**Files:**
- Modify: `Kintsugi_CVE_Case_UI/app/page.tsx`
- Modify: `Kintsugi_CVE_Case_UI/app/globals.css`

- [ ] Render a request specimen and three-step execution chain from the selected profile.
- [ ] Render case-specific facts: marker file for command injection, upload/decoder boundary for Ghostscript, and target-network decision for SSRF.
- [ ] Keep the common before/after cards and live patch panel so cross-case comparison remains consistent.
- [ ] Add responsive styles without changing the approved restrained visual language.

### Task 4: Verify the finished UI

**Files:**
- Verify: `Kintsugi_CVE_Case_UI/app/**`
- Verify: `Kintsugi_CVE_Case_UI/tests/**`

- [ ] Run `npm test` and require zero failures.
- [ ] Run ESLint over app, tests, and configuration files and require zero errors.
- [ ] Run `npm run build` and require a successful production build.
- [ ] Exercise CVE switching and the attack → repair → same attack flow in the local page.
- [ ] Check `git status --short` to confirm existing tracked content was not modified.
