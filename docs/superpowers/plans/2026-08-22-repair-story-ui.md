# Repair Story UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保留 Kintsugi 现有主导航和检测修复功能的前提下，为“检测与修复”页增加修补概览、修改详情、防护机制和验证结果四个二级视图。

**Architecture:** 保持 `DetectionRepair` 的数据加载和代码 Diff 逻辑不变，新增一个无副作用的文案派生模块，把现有产物字段转换为可靠、通俗但专业的展示文案。页面只增加本地二级视图状态和局部 JSX，样式限定在检测与修复区域；Bridge API、产物格式及其他页面不变。

**Tech Stack:** React 19、TypeScript/TSX、Next.js 16、Vite/vinext、原生 CSS、Node.js test runner

---

## File map

- Create: `Kintsugi_CVE_UI/app/repair-story.mjs` — 纯函数，将修复方式、验证字段和源码位置派生为 UI 文案，不依赖 React 或浏览器。
- Create: `Kintsugi_CVE_UI/tests/repair-story.test.mjs` — 覆盖成功、失败、字段缺失、网络过滤和运行时白名单文案。
- Modify: `Kintsugi_CVE_UI/package.json` — 增加可单独执行的文案单元测试，并把它纳入完整测试。
- Modify: `Kintsugi_CVE_UI/app/page.tsx` — 在现有 `DetectionRepair` 内增加四个二级入口；原内容完整迁移到“修改详情”。
- Modify: `Kintsugi_CVE_UI/app/globals.css` — 增加二级入口、修补前后对比、防护路径和验证结论的局部样式及移动端换行规则。

### Task 0: Establish the verified baseline

**Files:**
- Verify only: `Kintsugi_CVE_UI/package-lock.json`

- [ ] **Step 1: Install the locked dependencies**

From `Kintsugi_CVE_UI`, run:

```powershell
npm ci
```

Expected: dependencies from `package-lock.json` install without modifying the lockfile.

- [ ] **Step 2: Run the existing test before changing source**

```powershell
npm test
```

Expected: the production build completes and `rendered-html.test.mjs` passes. If the baseline fails, stop and diagnose it before attributing the failure to this feature.

- [ ] **Step 3: Run the existing lint baseline**

```powershell
npm run lint
```

Expected: exit 0. Record any pre-existing warning before source changes.

### Task 1: Add tested repair-story derivation

**Files:**
- Create: `Kintsugi_CVE_UI/tests/repair-story.test.mjs`
- Create: `Kintsugi_CVE_UI/app/repair-story.mjs`
- Modify: `Kintsugi_CVE_UI/package.json`

- [ ] **Step 1: Write the failing unit tests**

Create `Kintsugi_CVE_UI/tests/repair-story.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { deriveRepairStory } from "../app/repair-story.mjs";

test("describes a validated runtime-filter repair", () => {
  const story = deriveRepairStory({
    repairMethod: "syscall",
    functionName: "poll_for_data",
    functionPath: "/var/www/html/remote_agent.php",
    startLine: 320,
    endLine: 356,
    normalOk: true,
    maliciousBlocked: true,
    ruleCount: 6,
  });

  assert.equal(story.location, "remote_agent.php · poll_for_data() · 第 320–356 行");
  assert.equal(story.resultTone, "success");
  assert.match(story.resultSummary, /正常功能保持可用/);
  assert.match(story.protectionSummary, /运行时白名单过滤/);
  assert.equal(story.normalSummary, "正常功能保持可用");
  assert.equal(story.maliciousSummary, "恶意行为已被阻断");
});

test("describes network filtering without calling it a syscall repair", () => {
  const story = deriveRepairStory({repairMethod: "network", ruleCount: 2});
  assert.match(story.protectionSummary, /网络访问过滤/);
  assert.doesNotMatch(story.protectionSummary, /系统调用白名单/);
});

test("reports failed validation without claiming safety", () => {
  const story = deriveRepairStory({normalOk: false, maliciousBlocked: false});
  assert.equal(story.resultTone, "danger");
  assert.equal(story.normalSummary, "正常功能验证未通过");
  assert.equal(story.maliciousSummary, "恶意行为仍可能成功");
  assert.doesNotMatch(story.resultSummary, /安全|已修复完成/);
});

test("uses explicit missing-evidence language", () => {
  const story = deriveRepairStory({});
  assert.equal(story.location, "产物未记录源码位置");
  assert.equal(story.resultTone, "unknown");
  assert.equal(story.normalSummary, "尚无正常功能验证证据");
  assert.equal(story.maliciousSummary, "尚无恶意行为验证证据");
});
```

- [ ] **Step 2: Add a unit-test script and verify the test fails**

Update `Kintsugi_CVE_UI/package.json` scripts:

```json
"test:unit": "node --test tests/repair-story.test.mjs",
"test": "npm run build && node --test tests/repair-story.test.mjs tests/rendered-html.test.mjs"
```

Run:

```powershell
npm run test:unit
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `app/repair-story.mjs`.

- [ ] **Step 3: Implement the minimal derivation module**

Create `Kintsugi_CVE_UI/app/repair-story.mjs`:

```js
function fileName(path) {
  if (!path) return "";
  return String(path).replaceAll("\\", "/").split("/").filter(Boolean).at(-1) || "";
}

function functionLabel(name) {
  if (!name) return "";
  const value = String(name);
  return value.endsWith(")") ? value : `${value}()`;
}

export function deriveRepairStory(input = {}) {
  const {
    repairMethod,
    functionName,
    functionPath,
    startLine,
    endLine,
    normalOk,
    maliciousBlocked,
    ruleCount = 0,
  } = input;

  const locationParts = [fileName(functionPath), functionLabel(functionName)].filter(Boolean);
  if (startLine) locationParts.push(`第 ${startLine}–${endLine || startLine} 行`);

  const normalSummary = normalOk === true
    ? "正常功能保持可用"
    : normalOk === false ? "正常功能验证未通过" : "尚无正常功能验证证据";
  const maliciousSummary = maliciousBlocked === true
    ? "恶意行为已被阻断"
    : maliciousBlocked === false ? "恶意行为仍可能成功" : "尚无恶意行为验证证据";

  let resultTone = "unknown";
  let resultSummary = "当前产物尚不足以确认修补效果";
  if (normalOk === true && maliciousBlocked === true) {
    resultTone = "success";
    resultSummary = "正常功能保持可用，已覆盖的恶意行为被阻断";
  } else if (normalOk === false || maliciousBlocked === false) {
    resultTone = "danger";
    resultSummary = "本次验证未全部通过，需要继续复核修补方案";
  } else if (normalOk === true || maliciousBlocked === true) {
    resultTone = "review";
    resultSummary = "已有部分验证证据，仍需完成另一类验证";
  }

  const isNetwork = String(repairMethod || "").toLowerCase().includes("network");
  const protectionName = isNetwork ? "网络访问过滤" : "运行时白名单过滤";
  const protectionSummary = isNetwork
    ? `在目标函数的高风险网络访问处启用网络访问过滤，当前产物记录 ${ruleCount} 条规则。`
    : `在目标函数的高风险操作区间启用运行时白名单过滤，当前产物记录 ${ruleCount} 条规则。`;

  return {
    location: locationParts.length ? locationParts.join(" · ") : "产物未记录源码位置",
    resultTone,
    resultSummary,
    normalSummary,
    maliciousSummary,
    protectionName,
    protectionSummary,
  };
}
```

- [ ] **Step 4: Run the unit tests and verify they pass**

Run:

```powershell
npm run test:unit
```

Expected: 4 tests pass, 0 fail.

- [ ] **Step 5: Commit the derivation module and tests**

```powershell
git add -- Kintsugi_CVE_UI/app/repair-story.mjs Kintsugi_CVE_UI/tests/repair-story.test.mjs Kintsugi_CVE_UI/package.json
git commit -m "test: define repair story presentation rules"
```

### Task 2: Add four secondary views without removing existing content

**Files:**
- Modify: `Kintsugi_CVE_UI/app/page.tsx:1153`

- [ ] **Step 1: Add the helper import and local view type**

At the top of `page.tsx`, add:

```ts
import { deriveRepairStory } from "./repair-story.mjs";

type RepairDetailView = "summary" | "changes" | "protection" | "validation";
```

- [ ] **Step 2: Add local secondary-view state and derive evidence-backed copy**

At the start of `DetectionRepair`, before `useArtifactView`, add:

```ts
const [detailView, setDetailView] = useState<RepairDetailView>("summary");
```

Inside the branch where `artifact.records.length` is truthy, after the existing `detail` and metric derivations, add:

```ts
const validation = detail?.validation || {};
const repairStory = deriveRepairStory({
  repairMethod: detail?.repair_method || artifact.selected?.repair,
  functionName,
  functionPath: detail?.function_path,
  startLine: detail?.start_line,
  endLine: detail?.end_line,
  normalOk: validation.normal_ok,
  maliciousBlocked: validation.malicious_blocked,
  ruleCount: detail?.rules ?? artifact.selected?.rules ?? 0,
});
const protectionRules = (detail?.syscall_rules || []).slice(0, 3);
const storyTabs: Array<{id: RepairDetailView; label: string}> = [
  {id: "summary", label: "修补概览"},
  {id: "changes", label: "修改详情"},
  {id: "protection", label: "防护机制"},
  {id: "validation", label: "验证结果"},
];
```

- [ ] **Step 3: Preserve the original headline and artifact selector**

Keep the original `STAGE 7–9` eyebrow, `h2` text “检测与修复”, summary metrics, and `ArtifactSelector`. Immediately after `ArtifactSelector`, add:

```tsx
<nav className="repairdetailtabs" aria-label="检测与修复详情">
  {storyTabs.map(tab => <button
    key={tab.id}
    type="button"
    className={detailView === tab.id ? "active" : ""}
    aria-pressed={detailView === tab.id}
    onClick={() => setDetailView(tab.id)}
  >{tab.label}</button>)}
</nav>
```

- [ ] **Step 4: Add the new repair summary view**

Render when `detailView === "summary"`:

```tsx
<div className="repairstoryview">
  <section className="panel repairstoryhero">
    <div className="sectiontitle"><div><h3>修补概览</h3><span>{repairStory.location}</span></div></div>
    <h4>{repairStory.resultSummary}</h4>
    <p>{repairStory.protectionSummary}</p>
    <div className="repairbeforeafter">
      <div className="before"><span>修补前</span><b>高风险操作缺少局部约束</b><small>外部输入可能触发超出正常业务范围的行为。</small></div>
      <i>→</i>
      <div className="after"><span>修补后</span><b>{repairStory.protectionName}已加入目标函数</b><small>{repairStory.normalSummary}；{repairStory.maliciousSummary}。</small></div>
    </div>
  </section>
</div>
```

- [ ] **Step 5: Wrap the complete original UI as the change-details view**

Move the existing `repairsummary` and `sourcepanel` sections unchanged inside:

```tsx
{detailView === "changes" && <div className="repairdetailsview">
  {/* Existing repairsummary section, unchanged */}
  {/* Existing sourcepanel/code diff section, unchanged */}
</div>}
```

Do not change `buildLineDiff`, syntax highlighting, additions/removals, rank, score, analysis, validation metrics, source location, or directory rendering.

- [ ] **Step 6: Add the protection-mechanism view**

Render when `detailView === "protection"`:

```tsx
<section className="panel protectionstory">
  <div className="sectiontitle"><div><h3>防护机制</h3><span>{repairStory.protectionName}</span></div></div>
  <div className="protectionflow">
    <div><i>1</i><b>请求进入目标函数</b><small>{functionName}</small></div>
    <span>→</span>
    <div><i>2</i><b>修补逻辑生效</b><small>{repairStory.protectionSummary}</small></div>
    <span>→</span>
    <div><i>3</i><b>验证观察结果</b><small>{repairStory.maliciousSummary}</small></div>
  </div>
  <div className="protectionevidence"><b>专业证据</b><span>修复方式：{detail?.repair_method || artifact.selected?.repair || "产物未记录"}</span><span>规则数量：{detail?.rules ?? artifact.selected?.rules ?? 0}</span><code>{repairStory.location}</code></div>
  {protectionRules.length ? <div className="protectionrules">{protectionRules.map(rule => <div key={rule.name}><b>{rule.name}</b><span>{rule.count} 条允许规则</span></div>)}</div> : <p className="emptyevidence">当前产物未记录可展开的白名单摘要。</p>}
</section>
```

- [ ] **Step 7: Add the validation-result view**

Render when `detailView === "validation"`:

```tsx
<section className="panel repairvalidationstory">
  <div className="sectiontitle"><div><h3>验证结果</h3><span>本次运行产物</span></div></div>
  <div className="repairvalidationrows">
    <div className={validation.normal_ok === true ? "pass" : validation.normal_ok === false ? "fail" : "unknown"}><i>{validation.normal_ok === true ? "✓" : validation.normal_ok === false ? "×" : "—"}</i><div><b>{repairStory.normalSummary}</b><small>Normal validation</small></div></div>
    <div className={validation.malicious_blocked === true ? "pass" : validation.malicious_blocked === false ? "fail" : "unknown"}><i>{validation.malicious_blocked === true ? "✓" : validation.malicious_blocked === false ? "×" : "—"}</i><div><b>{repairStory.maliciousSummary}</b><small>Malicious validation</small></div></div>
  </div>
  <p className={`repairvalidationconclusion ${repairStory.resultTone}`}>{repairStory.resultSummary}。结论仅适用于本次运行覆盖的验证用例。</p>
  <dl><div><dt>总尝试</dt><dd>{totalAttempts} 次</dd></div><div><dt>产物目录</dt><dd>{artifact.selected?.directory}</dd></div></dl>
  {(detail?.log_tail || []).length ? <div className="repairvalidationlog">{(detail?.log_tail || []).slice(-8).map((line, index) => <code key={`${index}-${line}`}>{line}</code>)}</div> : <p className="emptyevidence">当前产物没有可显示的验证日志。</p>}
</section>
```

- [ ] **Step 8: Run lint/type validation before styling**

Run:

```powershell
npm run lint
```

Expected: no new TypeScript or ESLint errors. Layout may still be visually unstyled at this checkpoint.

- [ ] **Step 9: Commit the additive JSX integration**

```powershell
git add -- Kintsugi_CVE_UI/app/page.tsx
git commit -m "feat: add repair story detail views"
```

### Task 3: Add scoped styling and responsive behavior

**Files:**
- Modify: `Kintsugi_CVE_UI/app/globals.css`

- [ ] **Step 1: Add scoped desktop styles**

Append styles using only the new class names. Reuse existing CSS variables for surfaces and status colors:

```css
.repairdetailtabs { display:flex; gap:8px; flex-wrap:wrap; margin:0 0 18px; }
.repairdetailtabs button { border:1px solid var(--line); background:var(--glass-strong); color:var(--muted); border-radius:999px; padding:9px 14px; cursor:pointer; }
.repairdetailtabs button.active { color:var(--green-deep); border-color:var(--green); background:var(--green2); }
.repairstoryhero h4 { margin:18px 0 8px; font-size:20px; }
.repairstoryhero > p { color:var(--muted); }
.repairbeforeafter { display:grid; grid-template-columns:1fr auto 1fr; gap:14px; align-items:stretch; margin-top:18px; }
.repairbeforeafter > div { padding:16px; border-radius:12px; background:var(--glass-strong); }
.repairbeforeafter .before { border-top:3px solid var(--red); }
.repairbeforeafter .after { border-top:3px solid var(--green); }
.repairbeforeafter b,.repairbeforeafter small { display:block; margin-top:6px; }
.repairbeforeafter small { color:var(--muted); }
.repairbeforeafter > i { align-self:center; color:var(--accent); font-style:normal; }
.protectionflow { display:grid; grid-template-columns:1fr auto 1fr auto 1fr; gap:12px; align-items:stretch; margin-top:18px; }
.protectionflow > div { padding:16px; border-radius:12px; background:var(--glass-strong); }
.protectionflow b,.protectionflow small { display:block; margin-top:6px; }
.protectionflow small { color:var(--muted); }
.protectionflow > span { align-self:center; color:var(--muted); }
.protectionevidence { display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin-top:16px; color:var(--muted); }
.protectionrules { display:grid; gap:8px; margin-top:14px; }
.protectionrules > div { display:flex; justify-content:space-between; gap:12px; padding:10px 12px; border-bottom:1px solid var(--line); }
.protectionrules span,.emptyevidence { color:var(--muted); }
.repairvalidationrows { display:grid; gap:10px; margin-top:18px; }
.repairvalidationrows > div { display:flex; gap:12px; align-items:center; padding:14px; border-radius:12px; background:var(--glass-strong); }
.repairvalidationrows b,.repairvalidationrows small { display:block; }
.repairvalidationrows small { color:var(--muted); margin-top:4px; }
.repairvalidationrows .pass > i { color:var(--green); }
.repairvalidationrows .fail > i { color:var(--red); }
.repairvalidationconclusion { margin-top:14px; padding:13px; border-radius:10px; background:var(--glass-strong); }
.repairvalidationconclusion.success { color:var(--green); }
.repairvalidationconclusion.danger { color:var(--red); }
.repairvalidationlog { display:grid; gap:4px; margin-top:14px; padding:12px; border-radius:10px; background:#17201d; color:#a8b6af; }
.repairvalidationlog code { white-space:pre-wrap; overflow-wrap:anywhere; }
```

These names already exist in the current light and dark theme blocks: `--line`, `--glass-strong`, `--muted`, `--green`, `--green-deep`, `--green2`, and `--red`. Do not introduce duplicate theme tokens.

- [ ] **Step 2: Add narrow-screen reflow**

Inside the existing mobile media query, add:

```css
.repairdetailtabs { gap:6px; }
.repairdetailtabs button { flex:1 1 calc(50% - 6px); }
.repairbeforeafter,.protectionflow { grid-template-columns:1fr; }
.repairbeforeafter > i,.protectionflow > span { text-align:center; transform:rotate(90deg); }
```

- [ ] **Step 3: Build and run the complete test suite**

Run:

```powershell
npm test
```

Expected: verified production build succeeds; 4 repair-story tests and the existing rendered-HTML test pass.

- [ ] **Step 4: Run lint**

Run:

```powershell
npm run lint
```

Expected: exit 0 with no new warnings or errors.

- [ ] **Step 5: Commit scoped styles**

```powershell
git add -- Kintsugi_CVE_UI/app/globals.css
git commit -m "style: present repair evidence in plain language"
```

### Task 4: Browser regression and final verification

**Files:**
- Verify: `Kintsugi_CVE_UI/app/page.tsx`
- Verify: `Kintsugi_CVE_UI/app/globals.css`
- Verify: `Kintsugi_CVE_UI/tests/repair-story.test.mjs`

- [ ] **Step 1: Start the local UI against an available Bridge or the existing empty state**

Run the repository-supported development command after installing dependencies if needed:

```powershell
npm ci
npm run dev
```

Expected: Vite prints a local URL and the page loads without a runtime exception. If Bridge is unavailable, verify the local empty/offline state and use source/render tests for artifact-dependent content rather than fabricating data.

- [ ] **Step 2: Verify the seven main navigation labels are unchanged**

Expected labels, in order:

```text
运行总览
新建任务
运行控制台
检测与修复
白名单与验证
历史运行
最近结果
```

- [ ] **Step 3: Verify all four secondary views**

In “检测与修复”, confirm these labels are present and selectable:

```text
修补概览
修改详情
防护机制
验证结果
```

Confirm “修改详情” still contains the original detection summary, source position, repair analysis, validation metrics and code Diff.

- [ ] **Step 4: Verify responsive layout**

At approximately 736 px and 360 px widths, confirm:

- Main navigation remains usable.
- Secondary buttons wrap instead of overflowing.
- Before/after and protection-flow columns stack on narrow screens.
- Code Diff remains readable under the existing mobile rules.

- [ ] **Step 5: Run final repository checks**

```powershell
git diff --check
git status --short
npm run test:unit
npm test
npm run lint
```

Expected: no whitespace errors; only intended source/test changes are present; all commands exit 0.

- [ ] **Step 6: Commit any browser-QA adjustments**

If QA required CSS or accessibility fixes:

```powershell
git add -- Kintsugi_CVE_UI/app/page.tsx Kintsugi_CVE_UI/app/globals.css Kintsugi_CVE_UI/app/repair-story.mjs Kintsugi_CVE_UI/tests/repair-story.test.mjs Kintsugi_CVE_UI/package.json
git commit -m "fix: polish repair story interactions"
```

If no adjustment was needed, do not create an empty commit.
