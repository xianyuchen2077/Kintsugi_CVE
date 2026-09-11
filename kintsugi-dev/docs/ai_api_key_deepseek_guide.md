# AI API Key 原理与 DeepSeek 使用方法

本文档说明 AI API key 的基本原理，以及如何以 DeepSeek 为例配置 KINTSUGI 的 stage 8。

## 1. API key 是什么

API key 是访问云端模型服务的身份凭证。它通常是一串长字符串，用来告诉模型服务：

* 请求来自哪个账号或项目。
* 该账号是否有权限调用模型。
* 本次调用应该计入哪个额度或账单。
* 是否触发速率限制、余额限制或风控规则。

调用 AI API 时，API key 一般放在 HTTP 请求头里：

```text
Authorization: Bearer <API_KEY>
```

这里的 `Bearer` 表示“持有这个 token 的请求方拥有对应权限”。因此 API key 泄露后，别人可能直接消耗你的额度，甚至访问你账号下的部分资源。

## 2. LLM API 的基本组成

一次大模型 API 调用通常包含以下部分：

### 2.1 provider

`provider` 是模型服务提供方，例如 DeepSeek、OpenAI、OpenRouter 等。

在 KINTSUGI 项目中，相关配置位于：

```text
utils/repair_utils.py
```

项目当前支持：

```python
LLM_PROVIDER = "deepseek"
LLM_PROVIDER = "openrouter"
```

### 2.2 base_url

`base_url` 是 API 服务地址。DeepSeek 的 OpenAI 兼容接口地址是：

```text
https://api.deepseek.com
```

由于 DeepSeek API 兼容 OpenAI SDK，所以可以用 OpenAI Python SDK，只需要把 `base_url` 改成 DeepSeek 的地址。

### 2.3 model

`model` 指定调用哪个模型。训练中建议使用：

```text
deepseek-v4-pro
```

如果只做快速连通性测试，也可以使用：

```text
deepseek-v4-flash
```

项目旧配置中可能还有：

```text
deepseek-chat
```

该名称仍可能兼容一段时间，但官方文档已标注计划在 2026-07-24 废弃，因此训练文档和新配置建议使用 `deepseek-v4-pro`。

### 2.4 messages

`messages` 是对话内容，通常是一个数组：

```json
[
  {"role": "system", "content": "You are a cybersecurity expert."},
  {"role": "user", "content": "Please analyze this vulnerable code."}
]
```

常见角色：

* `system`：规定模型身份、任务边界和输出格式。
* `user`：用户输入，也就是本次真正要处理的材料。
* `assistant`：历史模型回复，多轮对话时需要带上。

DeepSeek 的 `/chat/completions` 是无状态接口。服务端不会自动记住上一轮上下文；如果要多轮对话，调用方必须把历史消息一起传入。

### 2.5 token 和 max_tokens

模型按 token 处理文本。token 可以粗略理解为模型看到的文本片段。

`max_tokens` 限制模型最多输出多少 token。KINTSUGI stage 8 需要模型返回插桩代码，所以输出上限不能太小。项目中默认使用：

```python
max_tokens = 8192
```

### 2.6 temperature

`temperature` 控制输出随机性：

* 较低值：输出更稳定，适合代码修复、结构化输出。
* 较高值：输出更多样，适合创意生成。

KINTSUGI 的策略插桩需要稳定结果，一般不需要调高 temperature。

### 2.7 stream

`stream=false` 表示等待完整结果返回。  
`stream=true` 表示边生成边返回。

KINTSUGI 需要拿到完整插桩结果后再解析，所以通常使用非流式调用。

## 3. DeepSeek API key 获取与保存

### 3.1 获取 key

基本流程：

1. 进入 DeepSeek 开放平台。
2. 登录账号。
3. 创建 API key。
4. 复制 key 并保存到本地安全位置。
5. 确认账号余额、额度和速率限制满足训练需要。

不要把 key 发到群里，也不要写进提交到仓库的文件中。

### 3.2 在 Linux 中设置环境变量

推荐使用环境变量保存 key：

```bash
export DEEPSEEK_API_KEY="你的 DeepSeek API key"
```

验证环境变量是否存在：

```bash
echo "$DEEPSEEK_API_KEY"
```

如果要长期生效，可以把 export 命令写入 `~/.bashrc` 或 `~/.zshrc`，但不要把真实 key 写进项目仓库。

## 4. 最小调用示例

### 4.1 curl 示例

```bash
curl https://api.deepseek.com/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${DEEPSEEK_API_KEY}" \
  -d '{
    "model": "deepseek-v4-pro",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello"}
    ],
    "thinking": {"type": "enabled"},
    "reasoning_effort": "high",
    "stream": false
  }'
```

如果返回正常 JSON，说明 key、网络和模型名基本可用。

### 4.2 Python 示例

先安装 SDK：

```bash
pip install openai
```

再运行：

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
)

response = client.chat.completions.create(
    model="deepseek-v4-pro",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "用一句话解释 API key 的作用。"},
    ],
    stream=False,
    reasoning_effort="high",
    extra_body={"thinking": {"type": "enabled"}},
)

print(response.choices[0].message.content)
```

## 5. 在 KINTSUGI 中配置 DeepSeek

KINTSUGI 的 LLM 调用在：

```text
utils/repair_utils.py
```

建议把配置改成读取环境变量：

```python
# LLM API provider: "deepseek" or "openrouter"
LLM_PROVIDER = "deepseek"

# DeepSeek config
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-v4-pro"
```

不建议写成：

```python
DEEPSEEK_API_KEY = "<your-api-key>"
```

原因是项目文件可能被提交、截图或共享，真实 key 容易泄露。

配置完成后，stage 8 会通过 OpenAI SDK 调用 DeepSeek：

```python
client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url=DEEPSEEK_BASE_URL
)
```

项目发送给模型的主要内容包括：

* system prompt：告诉模型它要做漏洞缓解插桩。
* user input：包含候选危险函数、源码上下文、syscall/network 差分信息。
* model output：模型返回带有 filter begin/end 的修复代码。

## 6. 运行 stage 8

先确认环境变量已设置：

```bash
echo "$DEEPSEEK_API_KEY"
```

再运行示例：

```bash
python main.py --cve CVE-2024-25737 --stage 8 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5
```

如果要从策略生成继续跑到验证：

```bash
python main.py --cve CVE-2024-25737 --stage 8-10 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5 \
  --validate-mode all
```

## 7. API key 安全规范

### 7.1 不要提交真实 key

不要把真实 key 写进：

* `utils/repair_utils.py`
* Markdown 文档
* 截图
* issue
* commit message
* 共享日志

### 7.2 使用环境变量

推荐：

```bash
export DEEPSEEK_API_KEY="..."
```

然后在 Python 中读取：

```python
os.environ.get("DEEPSEEK_API_KEY")
```

### 7.3 泄露后立即轮换

如果 key 可能泄露，应立即：

* 在平台删除或禁用旧 key。
* 创建新 key。
* 检查最近调用记录和余额。
* 查找项目中是否有硬编码 key。

### 7.4 日志中不要打印 key

调试时不要写：

```python
print(DEEPSEEK_API_KEY)
```

可以只打印是否存在：

```python
print(bool(DEEPSEEK_API_KEY))
```

## 8. 常见错误

### 8.1 401 Unauthorized

可能原因：

* API key 错误。
* 环境变量没有生效。
* 请求头没有带 `Authorization: Bearer ...`。
* 复制 key 时多了空格或换行。

### 8.2 402 或余额相关错误

可能原因：

* 账号余额不足。
* 当前项目没有可用额度。
* 计费方式未启用。

### 8.3 429 Too Many Requests

可能原因：

* 请求太频繁。
* 并发过高。
* 账号速率限制较低。

处理方式：

* 降低并发。
* 重试时增加等待时间。
* 避免多人共用同一个 key 同时跑 stage 8。

### 8.4 model not found

可能原因：

* 模型名写错。
* 使用了已废弃或当前账号不可用的模型。

建议优先使用：

```text
deepseek-v4-pro
```

### 8.5 输出无法被项目解析

可能原因：

* 模型没有按 prompt 输出完整代码。
* 输出被 `max_tokens` 截断。
* 输入源码上下文过长。
* 模型随机性过高。

处理方式：

* 提高 `max_tokens`。
* 减少无关源码上下文。
* 保持非流式调用。
* 使用更稳定的模型和较低随机性。

## 9. 模型对比实验建议

科研训练中不建议只使用一个最新强模型。可以有意识地更换多个 AI 模型进行对比，观察不同模型在 stage 8 中定位危险代码边界、生成插桩代码和保持输出格式方面的差异。

建议至少包含两类模型：

* 较新的强模型：用于观察当前最佳效果。
* 较老或能力较弱的模型：最好选择知识库中可能没有对应 CVE 信息的模型。

这样设计的目的，是验证 KINTSUGI 的效果是否主要来自运行时轨迹、源码上下文和正常/恶意差分，而不是来自模型提前“记住了某个 CVE 的答案”。

对比时应尽量保持其他条件一致：

* 使用同一个 CVE。
* 使用同一份 stage 7 检测结果。
* 使用同一份 prompt 和源码上下文。
* 使用相同的 `threshold`、`repair-mode` 和 `whitelist-mode`。
* 关闭或避免使用带联网搜索、RAG 检索、浏览器工具的模型模式。

每次实验建议记录：

* 模型名称和 provider。
* 调用日期。
* 是否成功生成可解析的修复代码。
* 插桩范围是否准确覆盖危险代码。
* stage 9 白名单是否能正常填充。
* stage 10 是否通过正常功能和恶意阻断验证。
* 失败原因，例如输出格式错误、插桩位置偏移、代码语法错误、误伤正常请求等。

如果较老模型也能在没有 CVE 先验知识的情况下生成可用插桩，说明这个方法更依赖项目提供的动态证据；如果只有最新模型能成功，则需要分析失败点是推理能力不足、代码能力不足，还是 prompt/上下文组织不清楚。

## 10. 在科研训练中的使用建议

* 每个小组使用独立 API key 或至少分时使用，避免互相影响额度和速率。
* 跑 stage 8 前先确认 stage 7 的检测结果合理，否则 LLM 会在错误候选函数上插桩。
* 保存每次 stage 8 的输入、输出和错误日志，便于复现实验。
* 不要让 LLM 直接决定 syscall 白名单；KINTSUGI 的设计是让 LLM 负责定位代码边界，白名单由正常流量轨迹生成。
* 如果模型输出明显不合理，优先检查流量脚本和差分结果，而不是反复盲目重跑 LLM。

## 11. 参考资料

* DeepSeek 官方文档：Your First API Call  
  https://api-docs.deepseek.com/
* DeepSeek 官方文档：API Authentication  
  https://api-docs.deepseek.com/api/deepseek-api/
* DeepSeek 官方文档：Create Chat Completion  
  https://api-docs.deepseek.com/api/create-chat-completion/
* DeepSeek 官方文档：Multi-round Conversation  
  https://api-docs.deepseek.com/guides/multi_round_chat/
* 项目配置文件：`utils/repair_utils.py`
