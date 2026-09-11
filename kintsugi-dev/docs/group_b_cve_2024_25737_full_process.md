# B 组示例：CVE-2024-25737 全过程解释

本文档介绍 B 组示例漏洞 `CVE-2024-25737` 的完整运行流程。该示例用于理解 KINTSUGI 如何处理 SSRF 类网络边界漏洞。

## 1. 示例基本信息

`CVE-2024-25737` 在本训练中作为 B 组示例：

* 语言：PHP。
* 应用类型：VuFind。
* 漏洞类型：SSRF。
* 训练重点：通过正常/恶意请求的网络连接差异定位危险代码，并在运行时限制危险网络访问。
* 示例目录：`cves/php/CVE-2024-25737/`。

项目配置位于：

```text
config/cves.yaml
```

关键配置：

```text
language: php
container: cve-2024-25737-env
port: 8081
manual_install: false
use_whitelist: true
use_attack_flag: true
```

这说明该 CVE 不需要手工初始化，容器启动后即可采集流量。

## 2. 漏洞基本原理

该 CVE 的核心接口是：

```text
GET /vufind/Cover/Show?proxy=<url>
```

正常情况下，VuFind 的封面功能会通过 `proxy` 参数获取合法外部封面图片。问题在于，如果服务端没有正确限制 `proxy` 指向的地址，攻击者就可以让服务端访问内部网络资源。

在该示例中：

* 正常请求让服务端访问合法外部图片地址。
* 恶意请求把 `proxy` 改成 Docker 内部服务地址。
* 内部服务只在实验网络中可见，外部用户本来不应该直接访问。
* 如果响应中出现内部服务标记，说明 SSRF 成功。

因此，该 CVE 的关键差异不是 syscall 类型，而是网络连接目标。正常请求访问外部封面服务，恶意请求访问内部服务。

## 3. 环境组成

环境文件位于：

```text
cves/php/CVE-2024-25737/env/
```

主要文件：

* `Dockerfile`：构建 PHP 7.4 + Apache + VuFind 环境。
* `docker-compose.yml`：启动 Web、MySQL 和内部测试服务。
* `internal-api/index.html`：模拟内部服务首页。
* `internal-api/secret.json`：模拟内部敏感接口。
* `99-tracer-filter.ini`：PHP tracer 和 filter 扩展配置。
* `init-db.sql`：数据库初始化相关文件。

容器组成：

```text
cve-2024-25737-env       VuFind Web 应用
cve-2024-25737-db        MySQL 数据库
cve-2024-25737-internal  内部测试服务
```

端口映射：

```text
localhost:8081 -> web container:80
```

内部服务 `cve-2024-25737-internal` 和 Web 应用处于同一个 Docker bridge 网络中。外部浏览器不能直接用该容器名访问它，但 Web 应用容器可以访问它。这正好模拟 SSRF 攻击中的“服务器能访问内部资源”。

白名单源码范围：

```text
cves/php/CVE-2024-25737/whitelist.txt
```

内容为：

```text
/usr/local/vufind/module/VuFind/src/VuFind
```

这表示源码提取和修复关注 VuFind 的核心源码目录。

## 4. 流量脚本设计

该 CVE 的流量脚本位于：

```text
cves/php/CVE-2024-25737/normal.py
cves/php/CVE-2024-25737/malicious.py
```

### 4.1 正常流量

`normal.py` 的目标是模拟合法封面访问行为。

核心设计：

* 使用 Locust 的 `HttpUser`。
* 主要访问同一个接口：`GET /vufind/Cover/Show`。
* 覆盖 `proxy`、`isbn`、`issn` 三类正常用法。
* 正常 `proxy` 指向合法外部图片服务。

任务权重：

```text
fetch_cover_with_proxy: 权重 3
fetch_cover_by_isbn:    权重 2
fetch_cover_by_issn:    权重 1
```

正常请求中最关键的是：

```text
/vufind/Cover/Show?proxy=<合法外部图片 URL>
```

它和恶意请求使用相同业务入口，但网络目标不同。

### 4.2 恶意流量

`malicious.py` 的目标是稳定触发 SSRF。

恶意目标包括：

```text
http://cve-2024-25737-internal/
http://cve-2024-25737-internal/secret.json
```

恶意请求仍然访问：

```text
/vufind/Cover/Show?proxy=...
```

只是把 `proxy` 参数替换成内部服务地址。

恶意请求特征：

* 请求头包含 `X-Attack-Flag: true`。
* 响应中如果出现内部服务标记，则认为 SSRF 成功。
* 成功标记包括内部 API 标识、敏感字段名和 `ssrf_confirmed`。

这个设计保证正常和恶意流量走同一个封面代理逻辑，便于 KINTSUGI 定位真正的 SSRF 触发点。

## 5. 运行时过滤器准备

该 CVE 属于 SSRF，最终依赖 network filter 阻断内部网络访问。network filter 不是 eBPF，而是基于 cgroup + iptables：

* `net_filter_begin/end` 把当前线程写入特定 cgroup。
* cgroup 给该线程发出的网络包打 classid。
* 容器网络命名空间中的 iptables 根据 classid 拦截内网访问。

`stage 1` 会执行 `net_filter/setup.sh` 并部署 PHP 侧 `net_filter.php`。`stage 10` 如果检测到 `network` 类型修复，也会重新执行 `net_filter/setup.sh`，并根据 stage 9 生成的网络白名单配置规则。

单独调试 network filter 时，可以在容器启动后手动运行：

```bash
sudo bash net_filter/setup.sh cve-2024-25737-env
```

注意：syscall 类漏洞才需要单独启动 eBPF loader：

```bash
sudo python3 syscall_filter/ebpf_load.py
```

本 CVE 的正常修复路径是 network filter，因此重点检查 cgroup/iptables 是否配置成功，而不是检查 eBPF loader。

## 6. 完整运行流程

进入项目根目录并激活 Python 环境：

```bash
cd /path/to/kintsugi-dev
source .venv/bin/activate
```

### Stage 0: up

启动 CVE 容器环境：

```bash
python main.py --cve CVE-2024-25737 --stage 0
```

本阶段会启动三个容器：

* VuFind Web 应用。
* MySQL 数据库。
* 内部测试服务。

Web 入口为：

```text
http://localhost:8081/vufind/
```

### Stage 1: build

构建运行时插桩组件：

```bash
python main.py --cve CVE-2024-25737 --stage 1
```

本阶段会为 PHP 应用准备函数调用栈追踪能力和运行时过滤能力。后续 KINTSUGI 需要把网络连接行为和 PHP 函数调用路径关联起来。

### Stage 2: collect

采集正常和恶意流量：

```bash
python main.py --cve CVE-2024-25737 --stage 2 \
  --normal-time 60 \
  --malicious-time 20
```

本阶段会执行：

```text
cves/php/CVE-2024-25737/normal.py
cves/php/CVE-2024-25737/malicious.py
```

同时使用 sysdig 采集容器 syscall 和网络行为。

预期结果：

* 正常流量访问合法封面图片、ISBN 或 ISSN 查询。
* 恶意流量通过 `proxy` 访问内部服务。
* 恶意请求中出现访问 `cve-2024-25737-internal` 的网络连接行为。

### Stage 3: parse

解析 sysdig 原始日志：

```bash
python main.py --cve CVE-2024-25737 --stage 3
```

本阶段把 sysdig 输出转换为结构化数据。对 SSRF 来说，重点字段包括：

* syscall 类型。
* 网络连接目标。
* 文件描述符。
* 进程名和线程 ID。
* HTTP 请求和响应内容。
* 事件时间。

### Stage 4: segment

按 HTTP 请求切分 syscall：

```bash
python main.py --cve CVE-2024-25737 --stage 4
```

切分逻辑位于：

```text
cves/php/CVE-2024-25737/unit.py
```

该脚本主要识别 Apache/PHP 请求：

* 请求开始：网络读事件中出现 HTTP 方法。
* 请求结束：同一连接上写回响应。
* 如果请求期间创建子进程，也会把相关子进程事件纳入同一个请求单元。
* 会过滤 MySQL 和 nginx 等无关进程，重点关注 Web 应用进程。

对于 SSRF，正确切分请求非常重要，因为后续需要知道某一次 `/vufind/Cover/Show?proxy=...` 请求是否导致了内部网络连接。

### Stage 5: callstack

重建函数调用栈：

```bash
python main.py --cve CVE-2024-25737 --stage 5
```

本阶段把网络行为和 PHP 函数调用路径对齐。需要重点观察：

* 哪些函数处理了 `/vufind/Cover/Show` 请求。
* 哪些函数最终发起了服务端网络访问。
* 正常请求和恶意请求的网络目标是否不同。

### Stage 6: extract

提取源码上下文：

```bash
python main.py --cve CVE-2024-25737 --stage 6
```

本阶段根据调用栈提取 VuFind 源码片段。该 CVE 的源码关注范围来自 `whitelist.txt`：

```text
/usr/local/vufind/module/VuFind/src/VuFind
```

理想情况下，提取结果应包含处理封面代理和 URL 获取逻辑的代码。

### Stage 7: detect

运行正常/恶意差分检测：

```bash
python main.py --cve CVE-2024-25737 --stage 7 --algo all
```

本阶段比较正常请求和恶意请求的行为差异，输出可疑函数排序。

理想结果：

* top 候选函数应接近封面代理或远程资源获取逻辑。
* 恶意请求对应的网络目标应指向内部服务。
* 正常请求对应的网络目标应是合法外部图片服务或正常业务依赖。

如果检测结果偏离很远，优先检查：

* 正常流量是否覆盖 `/vufind/Cover/Show?proxy=<合法 URL>`。
* 恶意流量是否真的访问到内部服务。
* stage 4 是否把请求和网络连接正确切到同一个请求单元中。

### Stage 8: repair

调用 LLM 生成运行时策略插桩代码：

```bash
python main.py --cve CVE-2024-25737 --stage 8 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5
```

该 CVE 属于 SSRF 类风险，因此重点是 network filter。

LLM 的任务是判断危险代码片段边界，并在服务端发起网络请求的位置附近插入策略开关。理想插桩形态是：

```text
进入危险片段 -> net_filter_begin(...)
执行远程 URL 获取
退出危险片段 -> net_filter_end(...)
```

需要检查：

* 插桩是否覆盖真正发起网络请求的代码。
* 插桩范围是否过大，是否影响 MySQL 或其他正常业务网络访问。
* 插桩是否放在异步、回调或间接调用之外导致失效。
* 修复后的 PHP 代码是否仍可运行。

### Stage 9: whitelist

基于正常流量生成网络白名单：

```bash
python main.py --cve CVE-2024-25737 --stage 9
```

本阶段会根据正常请求在危险代码片段中的网络行为，填充允许访问的目标。

该 CVE 的目标是：

* 保留合法封面代理访问。
* 保留正常业务依赖。
* 阻断访问内部测试服务。

如果正常流量覆盖不足，可能导致正常封面请求被误伤。正常脚本中保留 `proxy`、`isbn`、`issn` 多种合法路径，就是为了让白名单更接近真实业务行为。

### Stage 10: validate

验证修复效果：

```bash
python main.py --cve CVE-2024-25737 --stage 10 \
  --validate-mode all
```

验证逻辑位于：

```text
cves/php/CVE-2024-25737/validate.py
```

验证分为两部分：

* 正常请求：外部封面代理仍可使用，MySQL 登录相关功能不应被破坏。
* 恶意请求：访问内部服务时，不应返回内部服务标记或敏感字段。

判断标准：

```text
正常封面/数据库功能保留 + 内部服务数据未泄露 = 修复有效
```

运行本阶段时，项目会对 `network` 类型修复重新设置 `net_filter/setup.sh`。如果验证中内部访问没有被阻断，需要优先检查：

* 容器是否仍然运行。
* `docker-compose.yml` 是否挂载了 `/sys/fs/cgroup:/sys/fs/cgroup:rw`。
* `sudo bash net_filter/setup.sh cve-2024-25737-env` 是否执行成功。
* 容器网络命名空间中是否存在对应 iptables 规则。

对 SSRF 来说，HTTP 状态码不是唯一判断标准。请求超时、连接失败、无敏感标记，都可能表示内部访问已经被阻断。

### Stage 11: down

清理实验环境：

```bash
python main.py --cve CVE-2024-25737 --stage 11
```

每个 CVE 实验结束后都应该清理容器，避免数据库、内部服务或网络状态影响下一次实验。

## 7. 重点观察输出

运行后重点观察：

```text
data/php/CVE-2024-25737/callstack/
data/php/CVE-2024-25737/callstack_with_code/
data/php/CVE-2024-25737/detect/
data/php/CVE-2024-25737/repair/
data/php/CVE-2024-25737/repair_with_whitelist/
data/php/CVE-2024-25737/repair_validated/
```

观察顺序：

1. `callstack/`：确认 `/vufind/Cover/Show` 请求和网络连接是否被正确关联。
2. `callstack_with_code/`：确认源码上下文是否包含封面代理或远程资源获取逻辑。
3. `detect/`：确认 top 候选是否接近 SSRF 触发点。
4. `repair/`：检查 LLM 插桩位置。
5. `repair_with_whitelist/`：检查网络白名单是否被填充。
6. `repair_validated/`：查看最终验证结果。

## 8. 该示例的核心结论

`CVE-2024-25737` 展示的是 KINTSUGI 处理 SSRF 类漏洞的典型路径：

```text
同一接口正常/恶意 URL
  -> 恶意输入触发内部网络访问
  -> 差分检测定位危险函数
  -> LLM 只负责插入策略边界
  -> 正常流量生成网络白名单
  -> cgroup/iptables network filter 阻断内部访问
```

该示例的训练价值在于：它能清楚展示“用户输入不是直接执行代码，但会改变服务器访问网络目标”的过程，也能说明为什么 SSRF 类漏洞更适合用网络白名单和请求级网络过滤来缓解。
