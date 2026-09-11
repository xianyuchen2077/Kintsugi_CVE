function baseName(path) {
  if (!path) return "";
  return String(path).replaceAll("\\", "/").split("/").filter(Boolean).at(-1) || "";
}

function functionLabel(name) {
  if (!name) return "";
  const value = String(name).trim();
  return value.endsWith(")") ? value : `${value}()`;
}

function protectionCopy(method) {
  switch (method) {
    case "syscall":
      return {
        protectionName: "系统调用白名单",
        protectionSummary: "在危险操作执行前增加运行时白名单过滤，仅允许验证过的系统调用继续执行。",
      };
    case "network":
      return {
        protectionName: "网络访问白名单",
        protectionSummary: "在发起网络请求前校验目标地址，只放行符合规则的访问目标。",
      };
    case "direct":
    case "direct_localization":
    case "source":
      return {
        protectionName: "源码逻辑修补",
        protectionSummary: "直接收紧易受攻击的源码逻辑，在危险输入到达敏感操作前完成校验或阻断。",
      };
    default:
      return {
        protectionName: "针对性防护",
        protectionSummary: "在已定位的风险路径上增加限制，阻止恶意输入继续触发危险行为。",
      };
  }
}

export function deriveRepairStory(input = {}) {
  const {
    functionName,
    functionPath,
    repairMethod,
    lineRange,
    normalPassed,
    maliciousBlocked,
  } = input;

  const locationParts = [baseName(functionPath), functionLabel(functionName)];
  if (lineRange) locationParts.push(`${lineRange} 行`);
  const location = locationParts.filter(Boolean).join(" · ") || "修补位置待确认";
  const complete = normalPassed === true && maliciousBlocked === true;
  const resultSummary = complete
    ? "正常流程通过，恶意路径被阻断，修补形成完整验证闭环。"
    : "验证尚未形成完整证据：需要同时确认正常流程通过且恶意路径被阻断。";

  return {
    location,
    resultTone: complete ? "success" : "warning",
    resultSummary,
    normalSummary: normalPassed === true ? "正常流程通过" : "正常流程尚未通过",
    maliciousSummary: maliciousBlocked === true ? "恶意路径被阻断" : "恶意路径尚未确认阻断",
    ...protectionCopy(String(repairMethod || "").toLowerCase()),
  };
}
