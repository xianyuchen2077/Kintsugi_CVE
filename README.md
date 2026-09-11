# Kintsugi CVE Lab

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-22.13+-339933?logo=node.js&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-required-2496ED?logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/status-research%20prototype-7dc095)

Kintsugi B 组课程项目。仓库包含漏洞复现实验、修补流程、本地 Bridge，以及用于课堂汇报的案例展示界面。

这是研究原型，不是生产级安全产品。仓库中的攻击样本只能在本人拥有或明确获准使用的隔离环境中运行。

## 从哪里开始

仓库里有两个前端，用途不同：

- `Kintsugi_CVE_Case_UI`：课堂展示使用。它读取已经准备好的实验资料，用动画和图表解释正常流量、恶意流量和修补后恶意流量。默认不执行真实攻击，也不操作 Docker。
- `Kintsugi_CVE_UI`：实验控制台。它通过本地 Bridge 调用后端流程，适合调试和复现实验，需要 WSL/Linux、Docker 及 sudo 权限。

如果只是查看演示效果，直接运行 `Kintsugi_CVE_Case_UI` 即可。

## 目录结构

```text
Kintsugi_CVE/
├── Kintsugi_CVE_Case_UI/  # 三个案例的可视化展示界面
├── Kintsugi_CVE_UI/       # 实时实验控制台与启动脚本
├── kintsugi-dev/          # Stage 流程、CVE 脚本、Bridge 和过滤器
├── docs/                  # 项目设计与实施记录
└── .env.example           # 本地配置模板，不包含真实密钥
```

## 快速查看案例 UI

要求 Node.js 22.13 或更高版本。在仓库根目录执行：

```bash
cd Kintsugi_CVE_Case_UI
npm install
npm run dev
```

开发服务器通常使用：

```text
http://localhost:3000/
```

端口被占用时，以终端实际显示的地址为准。

案例 UI 目前包含：

- CVE-2022-46169：展示请求来源、命令边界和文件副作用。
- CVE-2018-16509：重点案例。通过正常图片、恶意 EPS 伪装图片和修补后恶意流量，解释 Ghostscript `%pipe%` 命令执行路径。
- CVE-2024-25737：展示 SSRF 请求如何尝试访问内部网络资源。

### CVE-2018-16509 建议演示顺序

1. 进入“漏洞定位”，分别选择正常样本和恶意样本，观察输入内容、处理路径及 `/tmp/got_rce` 文件状态。
2. 打开“修补解析”，查看输入检查的位置和代码变化。
3. 进入“结果对比”，并列播放正常流量、恶意流量和修补后恶意流量。
4. 点击证据区域，说明哪些结论来自实验报告，哪些画面只是攻击机制示意。

内置样本位于 `Kintsugi_CVE_Case_UI/public/case-samples/CVE-2018-16509/`。浏览器只读取样本内容，不会在前端执行其中的载荷。

## 启动实时实验控制台

实时控制台建议在 Ubuntu 或 Windows 的 WSL2 Ubuntu 中运行。需要：

- Python 3.12 或更高版本
- Node.js 22.13 或更高版本
- Docker Engine 和 Docker Compose
- 可用的 sudo 权限；需要内核观测时还要满足 eBPF 环境要求

### 1. 安装后端依赖

```bash
cd kintsugi-dev
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r bridge/requirements.txt
```

### 2. 安装控制台依赖

```bash
cd ../Kintsugi_CVE_UI
npm ci
```

### 3. 准备配置

在 `Kintsugi_CVE_UI` 目录中，把仓库根目录的配置模板复制为根目录 `.env`：

```bash
cp ../.env.example ../.env
```

本机模式不需要 Bridge token。只有使用 LLM 修补阶段时，才需要填写对应服务商的 API key。不要把 `.env` 提交到 Git。

`.env.example` 还列出了各漏洞容器使用的数据库和演示账户变量。运行对应案例前需要在本机 `.env` 中填写；仓库不再提供硬编码默认口令。

常用配置：

| 配置项 | 是否必填 | 说明 |
| --- | --- | --- |
| `KINTSUGI_ROOT` | 否 | 后端目录。保持默认目录结构时会自动识别 |
| `KINTSUGI_BRIDGE_TOKEN` | 远程模式必填 | Bridge 远程访问口令 |
| `KINTSUGI_SUDO_PASSWORD` | 否 | 自动执行 sudo 操作；留空时由交互式终端询问 |
| `LLM_PROVIDER` | 使用 LLM 时必填 | `deepseek`、`paratera` 或 `openrouter` |
| `DEEPSEEK_API_KEY` | 按服务商填写 | DeepSeek API key |
| `PARATERA_API_KEY` | 按服务商填写 | Paratera API key |
| `OPENROUTER_API_KEY` | 按服务商填写 | OpenRouter API key |

### 4. 启动

在 `Kintsugi_CVE_UI` 目录执行：

```bash
./start.sh local
```

控制台默认地址：

```text
http://127.0.0.1:5173/
```

远程访问模式会监听 `0.0.0.0`，必须先设置 `KINTSUGI_BRIDGE_TOKEN`：

```bash
./start.sh token
```

不要把 Bridge、Docker API 或漏洞容器直接暴露到公网。

### Windows 用户

`start.sh` 是 Bash 脚本。请先进入 WSL2 Ubuntu，再切换到仓库目录运行。例如：

```bash
wsl -d Ubuntu
cd /mnt/<盘符>/<仓库路径>/Kintsugi_CVE_UI
./start.sh local
```

`<盘符>` 和 `<仓库路径>` 需要替换成本机实际位置。

## 数据与证据边界

案例 UI 是展示层，不等同于实时 Docker 控制台。它会读取内置样本和已保存的实验结果，并按步骤播放后台处理过程。

CVE-2018-16509 页面中的 HTTP 200、1653 bytes、恶意请求 HTTP 500、`/tmp/got_rce` 未创建等信息来自现有实验报告。Stage 10 最终验证采用 Python 输入检查，不能表述为已经验证的内核 eBPF 拦截。缺少原始日志、时间戳或系统调用计数的部分会标注为“原理示意”。

部分 SSRF 实验目录包含名为 `secret.json` 的文件，以及形如密码、API key 的字符串。这些都是用于演示内部资源泄露效果的假数据，不是真实凭据。

运行产物默认保存在：

```text
kintsugi-dev/data/
```

## 验证

案例 UI：

```bash
cd Kintsugi_CVE_Case_UI
npm test
npm run build
```

实时控制台：

```bash
cd Kintsugi_CVE_UI
npm test
```

## 当前进度

- [x] 建立独立案例展示 UI，并为三个案例提供分页面演示。
- [x] 完成 CVE-2018-16509 的三种流量对比、容器文件观察和证据说明。
- [x] 保留本地 Bridge 适配层，明确当前页面是否实际调用。
- [ ] 在不同 Windows/WSL、Ubuntu、Docker 和 Node.js 版本上完成兼容性验证。
- [ ] 复现并稳定 CVE-2021-33926、CVE-2025-31116 的完整运行流程。
- [ ] 为三个案例补齐统一格式的原始运行记录和证据来源。
- [ ] 录制课堂演示视频，并准备现场演示失败时的备用材料。
- [ ] 整理答辩 QA，覆盖漏洞原理、修补范围、性能影响和实验限制。

## 使用范围

本仓库仅用于课程研究、授权安全测试和防御技术验证。请勿对不属于自己或未获得授权的系统运行其中的攻击脚本。
