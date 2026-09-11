# Kintsugi CVE UI

Kintsugi 本地 Web 控制台。前端展示任务、日志和结果；Bridge 在本机调用 `kintsugi-dev/main.py`。

## 目录放置

推荐把两个目录放在同一级：

```text
summer/
├── kintsugi-dev/
└── Kintsugi_CVE_UI/
```

如果后端目录不是 `kintsugi-dev`，启动前指定：

```env
KINTSUGI_ROOT=/path/to/kintsugi-dev
```

上传包根目录提供 `.env.example`。推荐复制为 `.env` 后统一填写配置，`start.sh` 会自动读取：

```bash
cp ../.env.example ../.env
```

## 首次安装

```bash
cd /path/to/Kintsugi_CVE_UI
npm ci
```

安装 Bridge 依赖：

```bash
cd /path/to/kintsugi-dev
source .venv/bin/activate
python -m pip install -r bridge/requirements.txt
```

如果后端里还没有 `bridge/`，`start.sh` 会自动把本项目自带的 `bridge/` 复制进去。

## 启动

本机使用：

```bash
cd /path/to/Kintsugi_CVE_UI
./start.sh local
```

远程设备访问：

```bash
./start.sh token
```

token 模式没有默认口令，需要先在根目录 `.env` 填写 `KINTSUGI_BRIDGE_TOKEN`。本机 `local` 模式不需要 token，只监听 `127.0.0.1`。

后台启动：

```bash
./start.sh local background
./start.sh token background
```

查看状态 / 停止：

```bash
./start.sh status
./start.sh stop
```

如果需要 sudo 自动执行：

```env
KINTSUGI_SUDO_PASSWORD=你的sudo密码
```

也可以不填，脚本会在交互式启动时询问一次；不会写入文件。

## 访问

本机：

```text
http://127.0.0.1:5173/
```

同一网络的其他设备：

```text
http://这台电脑的IP:5173/
```

## 使用

1. 选择 CVE。
2. 进入“新建任务”配置 Stage 范围和参数。
3. 提交后在“运行控制台”查看队列、进度和实时日志。
4. 运行结束后在“运行总览”、“检测与修复”、“白名单与验证”、“历史运行”、“最近结果”查看产物。

常用 Stage：

```text
0-10    全流程
8-10    重新生成修复、白名单、验证
10      只验证已有修复
11      清理环境
```

## 结果位置

结果保存在 Kintsugi 后端目录：

```text
kintsugi-dev/data/php/CVE-xxxx-xxxxx-YYYYMMDD-HHMMSS/
kintsugi-dev/data/python/CVE-xxxx-xxxxx-YYYYMMDD-HHMMSS/
```
