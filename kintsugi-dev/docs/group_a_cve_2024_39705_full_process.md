# A 组示例：CVE-2024-39705 全过程解释

本文档介绍 A 组示例漏洞 `CVE-2024-39705` 的完整运行流程。该示例用于理解 KINTSUGI 如何处理反序列化导致的代码执行类漏洞。

## 1. 示例基本信息

`CVE-2024-39705` 在本训练中作为 A 组示例：

* 语言：Python。
* 应用类型：Flask Web 应用。
* 漏洞类型：不安全反序列化。
* 训练重点：通过正常/恶意请求的 syscall 差异定位危险代码，并在运行时限制危险 syscall。
* 示例目录：`cves/python/CVE-2024-39705/`。

项目配置位于：

```text
config/cves.yaml
```

关键配置：

```text
language: python
container: cve-2024-39705-env
port: 5002
manual_install: false
use_whitelist: true
use_attack_flag: true
```

该 CVE 不需要手工初始化，容器启动后即可采集流量。

## 2. 漏洞基本原理

漏洞应用代码位于：

```text
cves/python/CVE-2024-39705/env/app.py
```

核心接口是：

```text
POST /load_model
```

应用从表单参数 `model_data` 中读取 base64 编码后的数据，然后执行：

```python
raw_data = base64.b64decode(model_data)
model = pickle.loads(raw_data)
```

问题在于：`pickle.loads()` 会反序列化 Python 对象。如果输入来自不可信用户，攻击者可以构造带有 `__reduce__` 方法的对象，让反序列化过程调用系统函数。

在该示例中：

* 正常请求提交合法 pickle 数据，例如字典、列表、元组、集合等。
* 恶意请求提交恶意 pickle 对象，通过 `__reduce__` 触发 `os.system()`。
* 恶意命令使用 `touch /tmp/...` 创建测试文件，用于证明代码执行。

因此，该 CVE 的关键差异不是 URL 不同，而是同一个 `/load_model` 接口在处理不同输入时产生了不同 syscall 行为。正常反序列化只会进行普通计算和读写；恶意反序列化会触发 shell、进程创建或命令执行相关 syscall。

## 3. 环境组成

环境文件位于：

```text
cves/python/CVE-2024-39705/env/
```

主要文件：

* `Dockerfile`：基于 Python 3.7 Alpine 构建 Flask 应用环境。
* `docker-compose.yml`：启动漏洞应用容器。
* `app.py`：包含不安全 `pickle.loads()` 的 Web 应用。
* `tracer.ini`：Python tracer 配置。

端口映射：

```text
localhost:5002 -> container:5000
```

容器名：

```text
cve-2024-39705-env
```

白名单源码范围：

```text
cves/python/CVE-2024-39705/whitelist.txt
```

内容为：

```text
/app
```

源码提取和修复关注容器中的 `/app` 目录。

## 4. 流量脚本设计

该 CVE 的流量脚本位于：

```text
cves/python/CVE-2024-39705/normal.py
cves/python/CVE-2024-39705/malicious.py
```

### 4.1 正常流量

`normal.py` 的目标是模拟合法模型加载行为。

核心设计：

* 使用 Locust 的 `HttpUser`。
* 访问同一个接口：`POST /load_model`。
* 参数名固定为：`model_data`。
* 数据格式为：Python 对象 -> pickle -> base64。
* 构造多种合法对象，提高正常轨迹覆盖度。

正常数据包括：

* 简单字典。
* 深层嵌套字典。
* 权重数组和词表。
* 元组、集合、列表。
* 模拟 NLTK 标注结果。
* 包含 `None`、布尔值和空列表的配置对象。

任务权重：

```text
load_complex_model: 权重 3
load_simple_model:  权重 1
```

正常请求成功条件：

```text
HTTP 200
```

### 4.2 恶意流量

`malicious.py` 的目标是稳定触发反序列化代码执行。

恶意对象定义了 `__reduce__`：

```python
def __reduce__(self):
    return (os.system, (self.cmd,))
```

当服务端执行 `pickle.loads()` 时，会调用 `os.system(self.cmd)`。

训练中使用的命令是创建临时测试文件：

```text
touch /tmp/CVE_2024_39705_PWNED_<timestamp>_<random>.txt
```

恶意请求特征：

* 仍然访问 `POST /load_model`。
* 仍然提交 `model_data`。
* 增加请求头 `X-Attack-Flag: true`。
* 通过容器内文件是否创建判断攻击是否成功。

这个设计保证正常和恶意流量经过同一个核心函数，便于 KINTSUGI 找出真正的危险代码片段。

## 5. 运行时过滤器准备

该 CVE 属于反序列化 RCE，最终依赖 syscall filter 阻断危险 syscall。这里需要特别注意：`stage 1` 会构建和部署 Python 侧 `syscall_filter` 模块，但真正拦截 syscall 的 eBPF 程序需要在 Linux 宿主机上单独启动。

在执行修复验证前，另开一个终端，在项目根目录运行：

```bash
sudo python3 syscall_filter/ebpf_load.py
```

该进程需要保持运行。它会读取 `config/syscalls.yaml`，生成 eBPF 程序并加载到内核。修复代码中的 `syscall_filter_begin/end` 会通过 `prctl(999, ...)` 通知 eBPF 程序当前线程进入或退出过滤状态。

如果没有启动该 eBPF loader：

* `stage 8` 和 `stage 9` 仍然可以生成插桩代码和白名单。
* `stage 10` 中应用代码也可能成功调用 `syscall_filter_begin/end`。
* 但内核侧没有真正的 eBPF 程序执行拦截，恶意 syscall 可能不会被阻断。

如果只跑到差分定位阶段，即 `stage 0-7`，通常不需要启动 eBPF loader。需要验证 syscall 阻断效果时，必须启动。

## 6. 完整运行流程

进入项目根目录并激活 Python 环境：

```bash
cd /path/to/kintsugi-dev
source .venv/bin/activate
```

### Stage 0: up

启动 CVE 容器环境：

```bash
python main.py --cve CVE-2024-39705 --stage 0
```

本阶段会启动 Flask 漏洞应用，并将容器服务映射到：

```text
http://localhost:5002
```

可以用以下接口检查应用是否启动：

```text
GET /
GET /health
GET /list_models
```

### Stage 1: build

构建运行时插桩组件：

```bash
python main.py --cve CVE-2024-39705 --stage 1
```

本阶段的作用是为 Python 应用准备函数调用栈追踪能力。后续 syscall 采集只能看到内核事件，KINTSUGI 还需要知道这些 syscall 是由哪段 Python 代码触发的。

### Stage 2: collect

采集正常和恶意流量：

```bash
python main.py --cve CVE-2024-39705 --stage 2 \
  --normal-time 60 \
  --malicious-time 20
```

本阶段会执行：

```text
cves/python/CVE-2024-39705/normal.py
cves/python/CVE-2024-39705/malicious.py
```

同时使用 sysdig 采集容器 syscall。

预期结果：

* 正常流量中，多次合法 `pickle.loads()` 成功。
* 恶意流量中，恶意 pickle 触发命令执行。
* 数据目录中生成正常和恶意 syscall 日志。

### Stage 3: parse

解析 sysdig 原始日志：

```bash
python main.py --cve CVE-2024-39705 --stage 3
```

本阶段把 sysdig 输出转换为后续阶段更容易处理的结构化数据。关注字段包括：

* syscall 类型。
* 进程名。
* 线程 ID。
* 文件描述符。
* 网络读写内容。
* 事件时间。

### Stage 4: segment

按 HTTP 请求切分 syscall：

```bash
python main.py --cve CVE-2024-39705 --stage 4
```

切分逻辑位于：

```text
cves/python/CVE-2024-39705/unit.py
```

该脚本会识别 Flask HTTP 请求的开始和结束：

* 请求开始：网络读事件中出现 HTTP 方法，例如 `POST`。
* 请求结束：同一 socket 上写回 HTTP 响应。
* 如果请求期间创建子进程，也会把子进程事件合并到该请求单元中。

这一点对反序列化 RCE 很重要，因为恶意 payload 可能触发新的 shell 或子进程。如果不合并子进程事件，就可能漏掉真正的危险 syscall。

### Stage 5: callstack

重建函数调用栈：

```bash
python main.py --cve CVE-2024-39705 --stage 5
```

本阶段把 syscall 和 Python 函数调用路径对齐。需要重点观察：

* 哪些 syscall 出现在 `/load_model` 请求中。
* 哪些 syscall 靠近 `pickle.loads()`。
* 恶意请求是否出现进程创建或命令执行相关事件。

### Stage 6: extract

提取源码上下文：

```bash
python main.py --cve CVE-2024-39705 --stage 6
```

本阶段根据调用栈定位到容器内源码，并提取相关代码片段。该 CVE 的关键代码应当接近：

```text
/app/app.py
```

重点函数是：

```text
load_model()
```

### Stage 7: detect

运行正常/恶意差分检测：

```bash
python main.py --cve CVE-2024-39705 --stage 7 --algo all
```

本阶段比较正常请求和恶意请求的行为差异，输出可疑函数排序。

理想结果：

* top 候选函数应接近 `load_model()`。
* 关键危险位置应接近 `pickle.loads(raw_data)`。
* 恶意请求中应出现正常请求没有的危险 syscall。

如果检测结果偏离很远，优先检查：

* 正常流量是否真的经过 `/load_model`。
* 恶意流量是否稳定触发 `os.system()`。
* stage 4 是否正确切分请求单元。

### Stage 8: repair

调用 LLM 生成运行时策略插桩代码：

```bash
python main.py --cve CVE-2024-39705 --stage 8 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5
```

该 CVE 属于代码执行类风险，因此重点是 syscall filter。

LLM 的任务不是直接决定完整白名单，而是判断危险代码片段边界。理想插桩位置应包围反序列化危险点：

```text
进入危险片段 -> syscall_filter_begin(...)
执行 pickle.loads(...)
退出危险片段 -> syscall_filter_end(...)
```

需要检查：

* 插桩是否覆盖 `pickle.loads()`。
* 插桩范围是否过大。
* 插桩是否影响正常请求的返回逻辑。
* 代码是否仍能运行。

### Stage 9: whitelist

基于正常流量生成白名单：

```bash
python main.py --cve CVE-2024-39705 --stage 9
```

本阶段会根据正常请求在危险代码片段中的 syscall 行为，填充允许列表。

该 CVE 的目标是：

* 保留正常 pickle 加载所需 syscall。
* 阻断恶意反序列化触发的命令执行相关 syscall。

如果正常流量覆盖不足，白名单可能过窄，导致正常请求被误伤。

### Stage 10: validate

验证修复效果：

```bash
python main.py --cve CVE-2024-39705 --stage 10 \
  --validate-mode all
```

验证逻辑位于：

```text
cves/python/CVE-2024-39705/validate.py
```

验证分为两部分：

* 正常请求：提交合法 pickle 对象，应能正常处理。
* 恶意请求：提交恶意 pickle 对象，容器内不应生成测试文件。

判断标准：

```text
正常功能保留 + 恶意命令未执行 = 修复有效
```

运行本阶段前，确认另一个终端中的 eBPF loader 仍在运行：

```bash
sudo python3 syscall_filter/ebpf_load.py
```

注意：恶意请求的 HTTP 状态码不是唯一判断标准。即使服务端返回 200 或 500，只要测试文件没有创建，就说明 syscall 限制发挥了作用。

### Stage 11: down

清理实验环境：

```bash
python main.py --cve CVE-2024-39705 --stage 11
```

每个 CVE 实验结束后都应该清理容器，避免临时文件、网络状态或容器状态影响下一次实验。

## 7. 重点观察输出

运行后重点观察：

```text
data/python/CVE-2024-39705/callstack/
data/python/CVE-2024-39705/callstack_with_code/
data/python/CVE-2024-39705/detect/
data/python/CVE-2024-39705/repair/
data/python/CVE-2024-39705/repair_with_whitelist/
data/python/CVE-2024-39705/repair_validated/
```

观察顺序：

1. `callstack/`：确认请求和 syscall 是否被正确关联。
2. `callstack_with_code/`：确认源码上下文是否包含 `app.py` 和 `load_model()`。
3. `detect/`：确认 top 候选是否接近 `pickle.loads()`。
4. `repair/`：检查 LLM 插桩位置。
5. `repair_with_whitelist/`：检查白名单是否被填充。
6. `repair_validated/`：查看最终验证结果。

## 8. 该示例的核心结论

`CVE-2024-39705` 展示的是 KINTSUGI 处理代码执行类漏洞的典型路径：

```text
同一接口正常/恶意输入
  -> 恶意输入触发额外 syscall
  -> 差分检测定位危险函数
  -> LLM 只负责插入策略边界
  -> 正常流量生成 syscall 白名单
  -> eBPF syscall filter 阻断命令执行
```

该示例的训练价值在于：它能清楚展示“输入看起来只是数据，但反序列化时可能变成代码执行”的过程，也能说明为什么 KINTSUGI 不直接修改业务逻辑，而是在危险代码片段周围做请求级运行时限制。
