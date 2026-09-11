#!/bin/bash

# syscall_filter PHP扩展自动编译脚本
# 用途: 在指定CVE容器中编译syscall_filter.so扩展

set -e

# 接收参数
CVE_ENV_DIR="$1"
CONTAINER_NAME="$2"

# 验证参数
if [ -z "$CVE_ENV_DIR" ] || [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <cve_env_dir> <container_name>"
    echo "Example: $0 cves/CVE-2021-26120/env env-web-1"
    exit 1
fi

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
# 将CVE_ENV_DIR转换为绝对路径
CVE_ENV_DIR="$(cd "$CVE_ENV_DIR" && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# 检查Docker是否运行
check_docker() {
    log "检查Docker状态..."
    if ! docker info >/dev/null 2>&1; then
        error "Docker未运行或无权限访问。请确保Docker已启动。"
    fi
    success "Docker运行正常"
}

# 启动容器
start_container() {
    log "启动CVE容器: $CONTAINER_NAME"
    cd "$CVE_ENV_DIR"
    rm -rf "$CVE_ENV_DIR/syscall_filter.so"
    touch "$CVE_ENV_DIR/syscall_filter.so"

    # 检查容器是否存在
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log "容器已存在，启动容器..."
        docker start "$CONTAINER_NAME"
    else
        log "容器不存在，创建并启动..."
        docker compose up -d
    fi

    # 等待容器完全启动
    log "等待容器启动完成..."
    sleep 5

    # 检查容器状态
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        success "容器启动成功"
    else
        error "容器启动失败"
    fi
}

# 停止容器
stop_container() {
    log "停止CVE容器: $CONTAINER_NAME"

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "$CONTAINER_NAME"
        success "容器已停止"
    else
        log "容器未运行，跳过停止步骤"
    fi
}

# 安装编译依赖
install_build_deps() {
    log "安装编译依赖..."

    # 安装依赖脚本
    INSTALL_SCRIPT='
set -e

echo "检查编译依赖..."

# Only need linux-libc-dev for <linux/bpf.h>
if ! dpkg -l | grep -q linux-libc-dev; then
    echo "安装 linux-libc-dev..."
    apt-get update -qq && apt-get install -y linux-libc-dev
    echo "✓ linux-libc-dev installed"
else
    echo "✓ linux-libc-dev already installed"
fi

echo "✓ Build dependencies ready (using direct syscalls, no libbpf)"
'

    if docker exec "$CONTAINER_NAME" bash -c "$INSTALL_SCRIPT"; then
        success "编译依赖安装完成"
    else
        error "安装编译依赖失败"
    fi
}

# 复制源码到容器
copy_source_to_container() {
    log "复制源码到容器: $CONTAINER_NAME"

    # 创建临时目录并复制源码
    docker exec "$CONTAINER_NAME" mkdir -p /tmp/syscall_filter_build
    docker cp "$SOURCE_DIR/syscall_filter.c" "$CONTAINER_NAME:/tmp/syscall_filter_build/"
    docker cp "$SOURCE_DIR/syscall_filter.h" "$CONTAINER_NAME:/tmp/syscall_filter_build/"
    docker cp "$SOURCE_DIR/config.m4" "$CONTAINER_NAME:/tmp/syscall_filter_build/"

    success "源码已复制到容器:/tmp/syscall_filter_build/"
}

# 在容器内编译
compile_in_container() {
    log "开始在容器内编译..."

    # 编译脚本
    COMPILE_SCRIPT='
set -e
cd /tmp/syscall_filter_build

echo "========================================="
echo "  Building syscall_filter.so"
echo "========================================="
echo ""

echo "=== [1/5] Cleaning previous build ==="
make clean 2>/dev/null || true
rm -rf .libs modules autom4te.cache configure

echo "=== [2/5] Running phpize ==="
phpize
if [ ! -f "configure" ]; then
    echo "ERROR: phpize failed - configure script not generated"
    exit 1
fi
echo "✓ phpize completed"

echo ""
echo "=== [3/5] Configuring build ==="
./configure --enable-syscall-filter
if [ $? -ne 0 ]; then
    echo "ERROR: configure failed"
    exit 1
fi
echo "✓ Configure completed"

echo ""
echo "=== [4/5] Compiling ==="
make
if [ $? -ne 0 ]; then
    echo "ERROR: make failed"
    exit 1
fi
echo "✓ Compilation completed"

echo ""
echo "=== [5/5] Verifying output ==="
ls -lh modules/
if [ -f "modules/syscall_filter.so" ]; then
    echo "✓ syscall_filter.so compiled successfully!"
    file modules/syscall_filter.so
else
    echo "ERROR: syscall_filter.so not found!"
    exit 1
fi

echo ""
echo "========================================="
echo "  Build Successful"
echo "========================================="
'

    # 在容器内执行编译
    if docker exec "$CONTAINER_NAME" bash -c "$COMPILE_SCRIPT"; then
        success "编译完成"
    else
        error "编译失败"
    fi
}

# 复制编译结果到CVE环境目录
copy_result_to_cve_env() {
    log "复制编译结果到CVE环境..."

    # 直接覆盖已挂载的syscall_filter.so文件，使用绝对路径
    if docker cp "$CONTAINER_NAME:/tmp/syscall_filter_build/modules/syscall_filter.so" "$CVE_ENV_DIR/syscall_filter.so"; then
        success "syscall_filter.so 已复制到 $CVE_ENV_DIR/"
    else
        error "复制编译结果失败"
    fi

    # 验证文件
    if [ -f "$CVE_ENV_DIR/syscall_filter.so" ]; then
        log "验证编译结果:"
        ls -la "$CVE_ENV_DIR/syscall_filter.so"
        file "$CVE_ENV_DIR/syscall_filter.so"
        success "编译完成！syscall_filter.so 可用。"
    else
        error "syscall_filter.so 文件不存在"
    fi
}

# 清理容器内的临时文件
cleanup() {
    log "清理临时文件..."

    docker exec "$CONTAINER_NAME" rm -rf /tmp/syscall_filter_build || true
    success "临时文件已清理"
}

# 主函数
main() {
    echo "======================================================"
    echo "       syscall_filter PHP扩展自动编译脚本"
    echo "======================================================"
    echo ""

    # 检查必要的目录和文件
    if [ ! -d "$CVE_ENV_DIR" ]; then
        error "CVE环境目录不存在: $CVE_ENV_DIR"
    fi

    if [ ! -f "$SOURCE_DIR/syscall_filter.c" ]; then
        error "源码文件不存在: $SOURCE_DIR/syscall_filter.c"
    fi

    if [ ! -f "$CVE_ENV_DIR/docker-compose.yml" ]; then
        error "Docker Compose配置不存在: $CVE_ENV_DIR/docker-compose.yml"
    fi

    # 执行编译流程
    check_docker
    start_container
    copy_source_to_container
    install_build_deps
    compile_in_container
    copy_result_to_cve_env
    cleanup
    stop_container

    echo ""
    echo "======================================================"
    success "编译流程完成！"
    echo "======================================================"
    echo ""
    echo "编译产物:"
    echo "  • $CVE_ENV_DIR/syscall_filter.so"
    echo ""
    echo "======================================================"
}

# 错误处理
trap 'error "脚本执行失败，请检查错误信息"' ERR

# 执行主函数
main "$@"
