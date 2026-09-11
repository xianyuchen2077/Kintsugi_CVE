# KINTSUGI 项目文件夹结构说明

本文档用于帮助学生快速理解仓库结构。阅读代码时建议先看 `main.py`、`config/cves.yaml`、一个示例 CVE 目录，再看各个 `stages/` 模块。

## 1. 顶层结构

```text
kintsugi-dev/
├── main.py
├── config.py
├── config/
├── cves/
├── stages/
├── stack_tracer/
├── syscall_filter/
├── net_filter/
├── sysdig_parser/
├── utils/
├── docs/
├── traffic_script_backups/
├── README.md
├── architecture.png
└── kintsugi.pdf
```

各目录作用：

* `main.py`：项目主入口，负责按 stage 调度完整流水线。
* `config.py`：读取 CVE 配置，生成 `CVEConfig` 对象。
* `config/`：全局配置，包括 CVE 列表和 syscall 列表。
* `cves/`：每个漏洞的实验环境、流量脚本、请求切分脚本和验证脚本。
* `stages/`：KINTSUGI 每个阶段的具体实现。
* `stack_tracer/`：函数调用栈追踪插件。
* `syscall_filter/`：基于 eBPF 的 syscall 过滤后端。
* `net_filter/`：基于 cgroup + iptables 的网络过滤后端。
* `sysdig_parser/`：sysdig 输出解析工具。
* `utils/`：容器操作、LLM 调用、白名单计算等辅助逻辑。
* `docs/`：科研训练文档。
* `traffic_script_backups/`：被清空前的原始流量脚本和验证脚本备份。
* `README.md`：项目总体说明。
* `kintsugi.pdf`：项目论文。

## 2. 主入口：main.py

`main.py` 是运行项目时最重要的文件。

常用命令：

```bash
python main.py --list
python main.py --cve CVE-2024-39705 --stage 0-11
python main.py --cve CVE-2024-25737 --stage 2-7
```

`main.py` 中定义了 stage 编号：

```text
0   up          启动容器
1   build       构建并安装插件
2   collect     采集正常/恶意流量
3   parse       解析 sysdig 日志
4   segment     按请求切分 syscall
5   callstack   重建调用栈
6   extract     提取源码上下文
7   detect      差分检测可疑函数
8   repair      调用 LLM 生成插桩代码
9   whitelist   基于正常流量填充白名单
10  validate    应用修复并验证
11  down        清理容器
```

学生调试时建议分阶段运行，而不是一开始直接跑 `0-11`。

## 3. 配置目录：config/

```text
config/
├── cves.yaml
└── syscalls.yaml
```

`config/cves.yaml` 定义每个 CVE 的基本信息：

* `language`：`php` 或 `python`。
* `version`：PHP 版本，Python CVE 通常为 `null`。
* `container`：目标容器名。
* `port`：宿主机访问端口。
* `use_whitelist`：是否在调用栈阶段使用源码白名单。
* `manual_install`：是否需要人工完成初始化。
* `repair_method`：指定修复后端，常见值为 `syscall`、`network` 或 `auto`。
* `python_path`：部分 Python 应用的解释器路径。

`config/syscalls.yaml` 定义 eBPF 程序需要关注的 syscall 列表。`syscall_filter/ebpf_load.py` 会读取这个文件并生成 eBPF 代码。

## 4. CVE 目录：cves/

`cves/` 按语言分为：

```text
cves/
├── php/
└── python/
```

每个 CVE 目录通常包含：

```text
cves/<language>/<CVE>/
├── env/
├── normal.py
├── malicious.py
├── unit.py
├── validate.py
└── whitelist.txt
```

各文件作用：

* `env/`：漏洞应用的 Docker 环境。
* `normal.py`：正常流量脚本，需要学生补写。
* `malicious.py`：恶意流量脚本，需要学生补写。
* `unit.py`：把 syscall 日志切分成 HTTP 请求单元。
* `validate.py`：验证正常功能保留和恶意请求阻断，需要学生补写。
* `whitelist.txt`：源码提取和调用栈过滤关注的路径。

目前两个示例 CVE 保留完整脚本：

```text
cves/python/CVE-2024-39705/
cves/php/CVE-2024-25737/
```

其余 CVE 的 `normal.py`、`malicious.py`、`validate.py` 已替换为训练占位文件。

## 5. CVE 的 env/ 目录

`env/` 是每个漏洞的运行环境，一般包含：

```text
env/
├── Dockerfile
├── docker-compose.yml
├── tracer.ini 或 99-tracer-filter.ini
└── 应用源码或初始化文件
```

常见文件：

* `Dockerfile`：构建漏洞应用镜像。
* `docker-compose.yml`：定义容器、端口、网络、数据库、内部服务等。
* `tracer.ini`：Python tracer 配置。
* `99-tracer-filter.ini`：PHP tracer/filter 扩展配置。
* `init-db.sql`：数据库初始化文件。

调试一个 CVE 时，先看 `docker-compose.yml`，确认端口、容器名、数据库和内部服务。

## 6. 流水线实现：stages/

```text
stages/
├── build.py
├── collect.py
├── parse.py
├── segment.py
├── callstack.py
├── extract_code.py
├── detect.py
├── repair.py
├── whitelist.py
└── validate.py
```

各文件对应主流程阶段：

* `build.py`：构建并部署 stack tracer、syscall filter、net filter。
* `collect.py`：启动 sysdig 和 Locust，采集正常/恶意轨迹。
* `parse.py`：把 sysdig 输出解析为 JSONL。
* `segment.py`：调用 CVE 目录下的 `unit.py` 切分请求。
* `callstack.py`：重建函数调用栈。
* `extract_code.py`：从容器中提取源码上下文。
* `detect.py`：对正常/恶意行为做差分检测。
* `repair.py`：组织 prompt，调用 LLM 生成插桩代码。
* `whitelist.py`：用正常流量填充 syscall/network 白名单。
* `validate.py`：应用修复代码，重启容器，调用 CVE 的 `validate.py` 验证效果。

学生如果只需要写流量脚本，重点看 `collect.py`、`segment.py` 和示例 CVE 的脚本即可。

## 7. 调用栈追踪：stack_tracer/

```text
stack_tracer/
├── php5/
├── php7/
├── php8/
└── python/
```

作用：记录一次请求中应用函数的调用路径。

PHP 部分通过 Zend extension 实现，不同 PHP 版本对应不同目录。  
Python 部分通过 Python tracer 模块实现。

`stage 1` 会根据 `config/cves.yaml` 中的语言和版本选择对应插件。

## 8. syscall 过滤：syscall_filter/

```text
syscall_filter/
├── ebpf_load.py
├── ebpf_code_gen.py
├── syscall_table.py
├── syscalls.h
├── php5/
├── php7/
├── php8/
└── python/
```

作用：为代码执行、命令注入、反序列化等漏洞提供 syscall 白名单阻断能力。

这里分为两部分：

* 语言侧模块：PHP 扩展或 Python 模块，负责在应用代码中调用 `syscall_filter_begin/end`。
* 宿主机 eBPF 程序：由 `syscall_filter/ebpf_load.py` 加载到内核，真正拦截 syscall。

重要：`stage 1` 会构建和部署语言侧模块，但不会长期托管 eBPF loader。要让 syscall filter 真正阻断 syscall，需要在 Linux 宿主机上单独启动：

```bash
sudo python3 syscall_filter/ebpf_load.py
```

该命令需要保持运行。关闭该进程后，eBPF 程序会卸载，`syscall_filter_begin/end` 只能发送控制信号，但内核侧不会执行阻断。

## 9. 网络过滤：net_filter/

```text
net_filter/
├── setup.sh
├── php/
└── python/
```

作用：为 SSRF 类漏洞提供网络访问限制。

核心机制：

* `net_filter_begin/end` 把当前线程写入特定 cgroup。
* cgroup 给线程发出的包打 classid。
* 容器网络命名空间中的 iptables 根据 classid 拦截内网或外网目标。

常用命令：

```bash
sudo bash net_filter/setup.sh <container_name>
```

`stage 1` 会安装 net_filter；`stage 10` 如果检测到 `network` 类型修复，也会重新配置 `net_filter/setup.sh` 并部署语言侧模块。

## 10. sysdig_parser/

```text
sysdig_parser/
├── parser.py
├── filter.lua
├── MessagePack.lua
└── fields.config
```

作用：配合 sysdig 采集和解析 syscall 日志。

一般不需要改这里。只有当 sysdig 字段缺失、日志格式不兼容、或者需要新增采集字段时，才需要阅读该目录。

## 11. utils/

```text
utils/
├── container.py
├── extract_source.py
├── path_compression.py
├── repair_utils.py
└── whitelist_utils.py
```

主要作用：

* `container.py`：读写容器内文件、应用修复代码、重启容器。
* `extract_source.py`：源码提取辅助逻辑。
* `path_compression.py`：路径白名单压缩。
* `repair_utils.py`：LLM API 调用和 prompt 模板。
* `whitelist_utils.py`：syscall/network 白名单计算。

配置 DeepSeek 或 OpenRouter 时，主要看 `utils/repair_utils.py`。

## 12. docs/

`docs/` 保存训练文档。

当前重点文档：

* `locust_traffic_script_guide.md`：Locust 和流量脚本编写。
* `ai_api_key_deepseek_guide.md`：DeepSeek API key 原理和使用。
* `group_a_cve_2024_39705_full_process.md`：A 组示例 CVE 全流程。
* `group_b_cve_2024_25737_full_process.md`：B 组示例 CVE 全流程。
* `project_structure_guide.md`：本文档。

## 13. 运行后生成的 data/

`data/` 目录通常在运行流水线后生成：

```text
data/<language>/<CVE>/
├── raw/
├── unit/
├── callstack/
├── callstack_with_code/
├── detect/
├── repair/
├── repair_with_whitelist/
└── repair_validated/
```

不同运行阶段生成的子目录可能略有差异。调试时重点看：

* `unit/`：请求切分结果是否合理。
* `callstack/`：syscall 是否和请求、函数调用栈关联成功。
* `callstack_with_code/`：是否提取到正确源码。
* `detect/`：可疑函数排序是否接近漏洞点。
* `repair/`：LLM 插桩是否合理。
* `repair_with_whitelist/`：白名单是否填充。
* `repair_validated/`：验证结果。

## 14. 学生建议阅读顺序

第一次上手建议按这个顺序看：

1. `README.md`：了解项目目标。
2. `docs/project_structure_guide.md`：了解目录结构。
3. `config/cves.yaml`：确认自己负责的 CVE。
4. 示例 CVE 目录：`cves/python/CVE-2024-39705/` 或 `cves/php/CVE-2024-25737/`。
5. `docs/locust_traffic_script_guide.md`：学习如何写流量脚本。
6. 自己负责的 `normal.py`、`malicious.py`、`validate.py`。
7. `unit.py`：理解请求切分逻辑。
8. `data/<language>/<CVE>/`：根据运行结果调试。

## 15. 常见修改位置

学生主要会修改：

```text
cves/<language>/<CVE>/normal.py
cves/<language>/<CVE>/malicious.py
cves/<language>/<CVE>/validate.py
```

通常不需要修改：

```text
stages/
stack_tracer/
syscall_filter/
net_filter/
sysdig_parser/
utils/
```

除非任务明确要求改框架本身，否则优先把问题定位在流量脚本、验证脚本和 CVE 环境配置上。
