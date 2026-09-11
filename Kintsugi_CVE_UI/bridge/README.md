# Kintsugi Local Bridge

将本目录复制到 Kintsugi 项目根目录后，在项目虚拟环境中安装依赖并启动：

```bash
cd /path/to/kintsugi-dev
python -m pip install -r bridge/requirements.txt
python -m uvicorn bridge.kintsugi_bridge:app --host 127.0.0.1 --port 8765
```

另开终端检查：

```bash
curl http://localhost:8765/health
```

预期返回 `status: ok`、Kintsugi 根目录、Docker 状态及 `main.py` 是否存在。

## 远程访问与 Token

如果使用项目自带 `start.sh`，推荐直接在 UI 目录启动：

```bash
./start.sh local
./start.sh token
```

`local` 为无 token 本机模式，只监听 `127.0.0.1`。

`token` 为远程模式，监听 `0.0.0.0`。token 模式没有默认口令，需要先在上传包根目录 `.env` 中填写：

```env
KINTSUGI_BRIDGE_TOKEN=your_token
```

token 模式下，前端会在进入控制台前要求输入 token；运行控制台内不再单独显示 token 输入框。

## 命令模板

默认调用：

```text
python main.py --cve {cve} --stage {start_stage}-{end_stage}
```

如果当前 Kintsugi 版本参数不同，在启动 Bridge 前设置模板。例如：

```bash
export KINTSUGI_COMMAND_TEMPLATE='python main.py --cve {cve} --stage {start_stage}-{end_stage}'
```

可用占位符：`{cve}`、`{start_stage}`、`{end_stage}`、`{collector}`、`{model}`。

## 接口

- `GET /health`：环境健康检查。
- `POST /preflight`：检查 Python、main.py、Docker、Sysdig、数据目录并预览命令。
- `GET /collectors`：实际探测 Sysdig 驱动与 Strace fallback 是否可用。
- `POST /runs`：创建运行任务。
- `GET /runs`：列出当前 Bridge 进程中的任务。
- `GET /runs/{run_id}`：查询任务状态。
- `GET /runs/{run_id}/events`：通过 SSE 获取实时日志。
- `POST /runs/{run_id}/cancel`：终止任务及其子进程组。

任务记录目前保存在内存中，重启 Bridge 后清空；Kintsugi 自身生成的文件不会被删除。
