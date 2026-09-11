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

如需从其他设备打开前端并控制这台电脑运行任务，启动前设置 token：

```bash
export KINTSUGI_BRIDGE_TOKEN='换成一段较长的随机密码'
python -m uvicorn bridge.kintsugi_bridge:app --host 0.0.0.0 --port 8765
```

前端“运行控制台”里填写：

```text
Bridge URL:   http://这台电脑的IP:8765
Bridge Token: 上面设置的 KINTSUGI_BRIDGE_TOKEN
```

不设置 `KINTSUGI_BRIDGE_TOKEN` 时保持原来的无 token 本机用法。

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
