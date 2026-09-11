# Locust 使用方法与流量脚本编写指南

本文档说明如何在 KINTSUGI 项目中使用 Locust 编写 `normal.py` 和 `malicious.py`。本训练要求学生独立完成流量脚本编写，所以重点不是压测，而是生成稳定、可切分、能触发关键函数差异的正常/恶意请求轨迹。

## 1. Locust 在本项目中的作用

KINTSUGI 的 stage 2 会同时采集 syscall 轨迹和 HTTP 流量。项目会对每个 CVE 分别执行：

```text
cves/<language>/<CVE>/normal.py
cves/<language>/<CVE>/malicious.py
```

其中：

* `normal.py` 负责发送正常业务请求。
* `malicious.py` 负责发送能触发漏洞的恶意请求。
* 两类请求应经过同一个漏洞相关函数。
* 正常请求要覆盖合法行为，恶意请求要稳定触发异常 syscall 或异常网络访问。

项目中的 `stages/collect.py` 会自动调用 Locust，核心命令等价于：

```bash
locust \
  -f cves/<language>/<CVE>/normal.py \
  --headless \
  --users 1 \
  --spawn-rate 1 \
  --run-time 60s \
  --host http://localhost:<port>
```

恶意流量也类似，只是脚本换成 `malicious.py`，运行时间换成 `--malicious-time` 指定的时间。

## 2. Locust 基本概念

Locust 脚本本质上是 Python 文件。

### 2.1 HttpUser

`HttpUser` 表示一种模拟用户。继承 `HttpUser` 后，可以通过 `self.client` 发送 HTTP 请求：

```python
from locust import HttpUser, task, between

class NormalUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def visit_home(self):
        self.client.get("/")
```

`self.client` 类似 `requests.Session`，会保留 cookie，所以适合模拟登录后的连续请求。

### 2.2 task

被 `@task` 标记的方法会被 Locust 反复执行。

```python
@task(3)
def common_action(self):
    self.client.get("/common")

@task(1)
def rare_action(self):
    self.client.get("/rare")
```

括号中的数字是权重。上例中，`common_action` 被选中的概率大约是 `rare_action` 的三倍。

### 2.3 wait_time

`wait_time = between(1, 3)` 表示每次任务完成后随机等待 1 到 3 秒。训练中不需要高并发，等待时间主要用于让请求轨迹更接近真实访问，并避免请求过密导致日志难以切分。

### 2.4 on_start

`on_start()` 会在每个模拟用户启动时执行，适合做登录、初始化 token、创建测试数据等操作：

```python
def on_start(self):
    self.client.post("/login", data={
        "username": "admin",
        "password": "admin"
    })
```

### 2.5 catch_response

`catch_response=True` 可以让脚本自己判断一次请求是否成功：

```python
with self.client.get("/api/status", catch_response=True) as response:
    if response.status_code == 200 and "ok" in response.text:
        response.success()
    else:
        response.failure("unexpected response")
```

这在恶意脚本中很重要，因为有些攻击请求即使 HTTP 状态码是 500，也可能已经触发了漏洞；也有些请求状态码是 200，但没有真正触发目标行为。

### 2.6 name 参数

如果 URL 中包含随机参数，可以用 `name` 把统计项归并起来：

```python
self.client.get(
    f"/item?id={item_id}",
    name="/item?id=[id]"
)
```

`name` 主要影响 Locust 输出统计，不直接决定 KINTSUGI 的 syscall 切分，但它能让调试更清楚。

## 3. 编写流量脚本的核心原则

### 3.1 正常和恶意请求要经过同一核心路径

KINTSUGI 依赖正常/恶意轨迹差分。如果正常请求和恶意请求走的是完全不同的业务入口，差分结果会被大量无关函数干扰。

好的写法：

* 正常请求访问 `/load_model`，提交合法模型数据。
* 恶意请求也访问 `/load_model`，提交恶意序列化数据。

不好的写法：

* 正常请求只访问首页。
* 恶意请求访问漏洞接口。

这种情况下，差分检测可能只学到“首页”和“漏洞接口”的业务差异，而不是漏洞行为差异。

### 3.2 正常流量要覆盖合法行为

正常脚本不是随便发一个请求。它应该覆盖漏洞函数在正常业务中的常见用法。

例如：

* 反序列化漏洞：正常请求应提交合法序列化数据，可以包含多种正常数据结构。
* SSRF 漏洞：正常请求应访问合法外部 URL，恶意请求访问内部服务或受限地址。
* 命令注入漏洞：正常请求应提交合法参数，恶意请求提交包含命令分隔符的参数。

正常流量覆盖越充分，stage 9 生成的白名单越接近真实业务需要。

### 3.3 恶意流量要稳定触发漏洞

恶意脚本应尽量做到：

* 每次运行都能稳定触发目标漏洞行为。
* 攻击结果有可判断标志，例如响应文本、状态码、内部服务标记、生成文件等。
* 不使用破坏性命令，训练中优先使用 `id`、`whoami`、`touch /tmp/kintsugi_test` 这类低风险验证命令。
* SSRF 类漏洞只访问实验环境中的内部服务，不访问真实外部敏感目标。

### 3.4 不要把脚本写成一次性 curl

Locust 脚本要能持续运行一段时间，让 sysdig 采集到足够轨迹。因此脚本应该放在 `@task` 中反复执行，而不是只在文件加载时发送一次请求。

### 3.5 不要依赖浏览器行为

`HttpUser` 不是浏览器。它不会渲染 HTML，不会自动执行 JavaScript，也不会自动加载页面中的图片、CSS 和 JS。如果漏洞触发依赖浏览器端逻辑，需要用脚本显式发送最终的 HTTP 请求。

## 4. 编写步骤

### 4.1 确认 CVE 配置

先查看：

```text
config/cves.yaml
```

重点确认：

* `language`：决定目录在 `cves/php/` 还是 `cves/python/`。
* `port`：Locust 的 `--host` 会使用这个端口。
* `manual_install`：如果为 `true`，需要先完成手工初始化。
* `repair_method`：如果是 `network`，通常是 SSRF 类漏洞；如果是 `syscall`，通常关注命令执行、代码执行或反序列化。
* `use_attack_flag`：如果为 `true`，恶意请求建议带上 `X-Attack-Flag: true` 便于后续区分。

### 4.2 确认目标端点

阅读 CVE 环境、README、PoC 或 `validate.py`，找出：

* 漏洞 URL。
* 漏洞参数。
* 是否需要登录。
* 是否需要 CSRF token。
* 正常输入长什么样。
* 恶意输入长什么样。
* 如何判断漏洞是否被触发。

### 4.3 先写最小正常请求

先保证一个正常请求能通：

```python
from locust import HttpUser, task, between

class NormalUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def normal_request(self):
        with self.client.get("/target?param=normal", catch_response=True) as response:
            if response.status_code in [200, 302, 404]:
                response.success()
            else:
                response.failure(f"unexpected status: {response.status_code}")
```

### 4.4 再扩展正常请求覆盖面

确认最小请求可用后，再加入多个合法输入：

```python
import random
from locust import HttpUser, task, between

NORMAL_VALUES = [
    "book-cover",
    "default-image",
    "public-resource",
]

class NormalUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def normal_target_path(self):
        value = random.choice(NORMAL_VALUES)
        with self.client.get(
            f"/target?param={value}",
            name="/target?param=[normal]",
            catch_response=True
        ) as response:
            if response.status_code < 500:
                response.success()
            else:
                response.failure(f"server error: {response.status_code}")
```

### 4.5 编写恶意请求

恶意请求应该只改变触发漏洞所需的关键输入，其余路径尽量与正常请求一致：

```python
from locust import HttpUser, task, between

class MaliciousUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def malicious_request(self):
        payload = "malicious-but-controlled-payload"
        headers = {"X-Attack-Flag": "true"}

        with self.client.get(
            f"/target?param={payload}",
            headers=headers,
            name="/target?param=[malicious]",
            catch_response=True
        ) as response:
            if response.status_code in [200, 500]:
                response.success()
            else:
                response.failure(f"unexpected status: {response.status_code}")
```

### 4.6 如需登录，在 on_start 中完成

```python
class LoginUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        response = self.client.post("/login", data={
            "username": "admin",
            "password": "admin"
        })
        if response.status_code not in [200, 302]:
            print(f"login failed: {response.status_code}")

    @task
    def request_after_login(self):
        self.client.get("/admin/dashboard")
```

如果应用需要 CSRF token，通常要先 `GET` 登录页，从 HTML 中解析 token，再提交登录表单。

## 5. 项目中的推荐模板

### 5.1 normal.py 模板

```python
#!/usr/bin/env python3

import random
from locust import HttpUser, task, between

NORMAL_INPUTS = [
    "normal-input-1",
    "normal-input-2",
    "normal-input-3",
]

class NormalUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        # 如果 CVE 不需要登录，可以删除该函数。
        pass

    @task(3)
    def normal_core_path(self):
        value = random.choice(NORMAL_INPUTS)
        with self.client.get(
            f"/vulnerable/path?param={value}",
            name="/vulnerable/path?param=[normal]",
            catch_response=True
        ) as response:
            if response.status_code < 500:
                response.success()
            else:
                response.failure(f"unexpected status: {response.status_code}")
```

### 5.2 malicious.py 模板

```python
#!/usr/bin/env python3

from locust import HttpUser, task, between

MALICIOUS_PAYLOADS = [
    "controlled-payload-1",
    "controlled-payload-2",
]

class MaliciousUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def exploit_core_path(self):
        for payload in MALICIOUS_PAYLOADS:
            with self.client.get(
                f"/vulnerable/path?param={payload}",
                headers={"X-Attack-Flag": "true"},
                name="/vulnerable/path?param=[malicious]",
                catch_response=True
            ) as response:
                if response.status_code in [200, 500]:
                    response.success()
                else:
                    response.failure(f"unexpected status: {response.status_code}")
```

## 6. 示例：CVE-2024-25737 的写法

`CVE-2024-25737` 是 SSRF 示例，正常和恶意请求都访问同一个接口：

```text
/vufind/Cover/Show?proxy=...
```

正常脚本使用合法外部图片 URL：

```python
with self.client.get(
    f"/vufind/Cover/Show?proxy={legal_image_url}",
    name="/vufind/Cover/Show?proxy=[EXTERNAL]",
    catch_response=True
) as response:
    response.success()
```

恶意脚本把 `proxy` 换成实验环境内部服务：

```python
with self.client.get(
    f"/vufind/Cover/Show?proxy=http://cve-2024-25737-internal/secret.json",
    name="/vufind/Cover/Show?proxy=[INTERNAL]",
    headers={"X-Attack-Flag": "true"},
    catch_response=True
) as response:
    if "ssrf_confirmed" in response.text:
        response.success()
    else:
        response.failure("internal marker not found")
```

这个例子的关键点是：正常和恶意请求都经过封面代理功能，但网络连接目标不同，所以后续差分会集中到 SSRF 相关网络行为。

## 7. 手动运行和调试

在 CVE 目录中可以手动运行：

```bash
cd cves/php/CVE-2024-25737
locust -f normal.py --host=http://localhost:8081 --headless -u 1 -r 1 -t 30s
locust -f malicious.py --host=http://localhost:8081 --headless -u 1 -r 1 -t 30s
```

参数含义：

* `-f`：指定流量脚本。
* `--host`：目标服务地址。
* `--headless`：不启动 Web UI，直接命令行运行。
* `-u` / `--users`：并发用户数。
* `-r` / `--spawn-rate`：每秒启动几个用户。
* `-t` / `--run-time`：运行时间。

在 KINTSUGI 主流程中运行：

```bash
python main.py --cve CVE-2024-25737 --stage 2 \
  --normal-time 60 \
  --malicious-time 20
```

如果本机配置了代理，导致 localhost 请求异常，可以临时设置：

```bash
NO_PROXY=localhost,127.0.0.1 locust -f normal.py --host=http://localhost:8081 --headless -u 1 -r 1 -t 30s
```

## 8. 质量检查清单

提交一个 CVE 的流量脚本前，至少检查：

* `normal.py` 和 `malicious.py` 都能被 Locust 正常加载。
* 两个脚本都能持续运行到指定时间，而不是启动后立刻退出。
* 正常请求和恶意请求尽量经过同一个漏洞相关接口。
* 正常请求不会误触发漏洞。
* 恶意请求能稳定触发漏洞行为。
* 恶意请求使用低风险验证动作，不破坏容器环境。
* 如果 `use_attack_flag: true`，恶意请求带有 `X-Attack-Flag: true`。
* `catch_response` 中的成功条件符合该 CVE 的真实触发逻辑。
* 请求参数、cookie、token 和登录流程都写在脚本中，不依赖人工浏览器操作。
* stage 2 能生成后续 stage 3-7 可用的数据。

## 9. 常见问题

### 9.1 脚本能手动 curl 成功，但 Locust 失败

常见原因：

* `--host` 写错。
* 请求路径多写了域名，应只写 `/path`。
* 缺少 cookie、CSRF token 或登录流程。
* 本机代理影响了 localhost 请求。
* 请求头和 PoC 中不一致。

### 9.2 stage 7 定位结果很差

常见原因：

* 正常请求没有经过漏洞函数。
* 恶意请求和正常请求入口差异过大。
* 正常流量覆盖太少，导致合法 syscall 被误判为异常。
* 恶意请求没有稳定触发漏洞。
* 请求太少，sysdig 轨迹不足。

### 9.3 恶意请求 HTTP 500 是否一定失败

不一定。很多漏洞触发后会返回 500，但危险行为已经发生。判断是否成功要看该 CVE 的触发标志，例如内部数据是否泄露、测试文件是否生成、命令输出是否出现、内部服务标记是否返回。

## 10. 参考资料

* Locust 官方文档：Writing a locustfile  
  https://docs.locust.io/en/stable/writing-a-locustfile.html
* Locust 官方文档：Running without the web UI  
  https://docs.locust.io/en/stable/running-without-web-ui.html
* 项目示例：`cves/php/CVE-2024-25737/normal.py`
* 项目示例：`cves/php/CVE-2024-25737/malicious.py`
