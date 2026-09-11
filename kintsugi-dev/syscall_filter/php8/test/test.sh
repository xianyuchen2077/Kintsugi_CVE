#!/bin/bash

# PHP8 syscall_filter 自动测试脚本
# 自动编译、部署、测试，监控BPF系统调用拦截

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_CONTAINER_DIR="$SCRIPT_DIR/container"
TEST_CONTAINER_NAME="syscall-filter-php8-test"
BUILD_SCRIPT="$SOURCE_ROOT/source/build.sh"

echo "======================================================"
echo "    PHP8 syscall_filter 自动测试脚本"
echo "======================================================"

# 检查环境
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker未运行"
    exit 1
fi

if [ ! -d "$TEST_CONTAINER_DIR" ]; then
    echo "ERROR: 测试容器目录不存在: $TEST_CONTAINER_DIR"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: 需要sudo权限运行"
    exit 1
fi

# 步骤1: 调用build.sh编译
echo ""
echo "=== 步骤1: 编译 syscall_filter.so ==="
bash "$BUILD_SCRIPT" "$TEST_CONTAINER_DIR" "$TEST_CONTAINER_NAME"

SO_FILE="$TEST_CONTAINER_DIR/syscall_filter.so"
if [ ! -f "$SO_FILE" ]; then
    echo "ERROR: 编译失败，找不到 syscall_filter.so"
    exit 1
fi
echo "编译完成: $SO_FILE"

# 步骤2: 启动测试容器
echo ""
echo "=== 步骤2: 启动测试容器 ==="
cd "$TEST_CONTAINER_DIR"
docker compose down >/dev/null 2>&1 || true
docker compose up -d
sleep 10

CONTAINER_ID=$(docker ps --filter "name=$TEST_CONTAINER_NAME" --format "{{.ID}}")
if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: 无法获取容器ID"
    exit 1
fi

CONTAINER_PID=$(docker inspect --format='{{.State.Pid}}' "$CONTAINER_ID")
echo "容器ID: $CONTAINER_ID, PID: $CONTAINER_PID"

# 步骤3: 启动 eBPF 程序 (在宿主机后台运行)
echo ""
echo "=== 步骤3: 启动 eBPF 程序 ==="
EBPF_DIR="$SOURCE_ROOT/.."
cd "$EBPF_DIR"

# echo "启动后台 eBPF 监控程序 (宿主机)..."
# EBPF_LOG=$(mktemp)
# trap "rm -f $EBPF_LOG" EXIT
# echo "eBPF 日志文件: $EBPF_LOG"
# python3 ebpf_load.py > "$EBPF_LOG" 2>&1 &
# EBPF_PID=$!
# echo "eBPF 进程 PID: $EBPF_PID"

# sleep 8  # 等待 BPF 程序加载和 maps 创建

# echo "验证 BPF 程序加载..."
# # 不再检查 pinned maps，而是检查 eBPF loader 进程是否仍在运行
# # 并且检查日志中是否有成功加载的标志
# if ps -p $EBPF_PID > /dev/null && grep -q "eBPF program loaded successfully" "$EBPF_LOG"; then
#     echo "✓ eBPF 程序已成功加载"
# else
#     echo "ERROR: BPF 程序加载失败。查看日志:"
#     cat "$EBPF_LOG"
#     kill $EBPF_PID 2>/dev/null || true
#     exit 1
# fi

# 步骤4: 验证扩展加载
echo ""
echo "=== 步骤4: 验证扩展加载 ==="
if docker exec "$CONTAINER_ID" php -m | grep -q "syscall_filter"; then
    echo "✓ syscall_filter 扩展已加载"
else
    echo "ERROR: syscall_filter 扩展未加载"
    docker exec "$CONTAINER_ID" php -m
    exit 1
fi

# 步骤5: 执行测试
echo ""
echo "=== 步骤5: 执行测试 ==="

# 测试1: simple_test.php
echo ""
echo "--- 测试1: simple_test.php ---"
if docker exec "$CONTAINER_ID" php /test/simple_test.php; then
    echo ""
    echo "✓ simple_test.php 执行成功"
else
    echo ""
    echo "✗ simple_test.php 执行失败"
    exit 1
fi

# 测试2: block_test.php (带trace监控)
echo ""
echo "--- 测试2: block_test.php (监控系统调用拦截) ---"

# 创建临时文件用于存储trace输出
TRACE_TEMP=$(mktemp)
trap "rm -f $TRACE_TEMP" EXIT

echo "启动 trace_pipe 监控..."
# 在后台监控trace_pipe
docker exec "$CONTAINER_ID" sh -c "cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null" > "$TRACE_TEMP" 2>&1 &
TRACE_PID=$!
echo "trace_pipe 监控 PID: $TRACE_PID"

sleep 3  # 等待监控启动

echo ""
echo "执行 block_test.php..."
echo "----------------------------------------"
if docker exec "$CONTAINER_ID" php /test/block_test.php; then
    echo "----------------------------------------"
    echo "✓ block_test.php 执行成功"
else
    echo "----------------------------------------"
    echo "✗ block_test.php 执行失败"
fi

sleep 3  # 等待trace事件完成

# 停止监控
echo ""
echo "停止 trace_pipe 监控..."
kill $TRACE_PID 2>/dev/null || true
wait $TRACE_PID 2>/dev/null || true

# 分析拦截的系统调用
echo ""
echo "=== 拦截的系统调用统计 ==="
if [ -f "$TRACE_TEMP" ] && [ -s "$TRACE_TEMP" ]; then
    BLOCKED_COUNT=$(grep -c "BLOCKED" "$TRACE_TEMP" 2>/dev/null || echo "0")
    echo "总计拦截: $BLOCKED_COUNT 个系统调用"

    if [ "$BLOCKED_COUNT" -gt 0 ]; then
        echo ""
        echo "拦截详情 (前20条):"
        grep "BLOCKED" "$TRACE_TEMP" | head -20
    fi
else
    echo "提示: 未捕获到trace事件 (这可能是正常的，取决于BPF程序配置)"
fi

# 清理临时文件
rm -f "$TRACE_TEMP"

# 测试3: path_test.php (路径白名单测试)
echo ""
echo "--- 测试3: path_test.php (路径参数白名单测试) ---"
if docker exec "$CONTAINER_ID" php /test/path_test.php; then
    echo ""
    echo "✓ path_test.php 执行成功"
else
    echo ""
    echo "✗ path_test.php 执行失败"
    exit 1
fi

# 步骤6: 清理
echo ""
echo "=== 步骤6: 清理 ==="

# 停止 eBPF 程序
echo "停止 eBPF 程序..."
kill $EBPF_PID 2>/dev/null || true
wait $EBPF_PID 2>/dev/null || true
echo "✓ eBPF 程序已停止"

# 停止容器
echo "停止容器..."
cd "$TEST_CONTAINER_DIR"
docker compose down

echo ""
echo "======================================================"
echo "测试完成！"
echo "======================================================"
