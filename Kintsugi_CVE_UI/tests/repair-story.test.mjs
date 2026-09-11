import test from "node:test";
import assert from "node:assert/strict";

import { deriveRepairStory } from "../app/repair-story.mjs";

test("把修补位置、方式和验证结果整理为易读摘要", () => {
  const story = deriveRepairStory({
    functionName: "poll_for_data",
    functionPath: "src/remote_agent.php",
    repairMethod: "syscall",
    lineRange: "250–435",
    normalPassed: true,
    maliciousBlocked: true,
  });

  assert.equal(story.location, "remote_agent.php · poll_for_data() · 250–435 行");
  assert.match(story.protectionSummary, /运行时白名单过滤/);
  assert.equal(story.resultTone, "success");
  assert.match(story.resultSummary, /正常流程通过/);
  assert.match(story.resultSummary, /恶意路径被阻断/);
});

test("在验证结果不完整时不宣称修补已生效", () => {
  const story = deriveRepairStory({
    functionName: "",
    functionPath: "",
    repairMethod: "source",
    lineRange: "",
    normalPassed: true,
    maliciousBlocked: false,
  });

  assert.equal(story.location, "修补位置待确认");
  assert.equal(story.resultTone, "warning");
  assert.match(story.resultSummary, /尚未形成完整证据/);
});
