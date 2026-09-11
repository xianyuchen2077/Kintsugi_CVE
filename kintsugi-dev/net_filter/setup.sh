#!/bin/bash
# net_filter setup - 宿主机运行，设置 cgroup 和容器内 iptables
# 用法: sudo ./setup.sh <容器名>

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# ============================================================================
# 参数处理
# ============================================================================

CONTAINER=$1
WHITELIST_IPS=$2  # 可选：逗号分隔的白名单 IP/CIDR 列表

if [ -z "$CONTAINER" ]; then
    echo "==========================================================================="
    echo " net_filter - 网络动态拦截设置"
    echo "==========================================================================="
    echo ""
    print_error "未指定容器名"
    echo ""
    echo "用法: sudo $0 <容器名> [白名单IP]"
    echo ""
    echo "参数:"
    echo "  容器名     必需，Docker 容器名称"
    echo "  白名单IP   可选，逗号分隔的 IP/CIDR 列表，这些内网 IP 不会被拦截"
    echo ""
    echo "示例:"
    echo "  sudo $0 net-filter-python-test"
    echo "  sudo $0 cve-web-1"
    echo "  sudo $0 cve-web-1 \"192.168.1.100,192.168.2.0/24\""
    exit 1
fi

CGROUP_BASE="/sys/fs/cgroup/net_cls"
INTERNAL_RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# ============================================================================
# 检查前置条件
# ============================================================================

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    print_error "请使用 root 权限运行此脚本"
    echo "用法: sudo $0 <容器名>"
    exit 1
fi

# 检查容器是否运行
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    print_error "容器 '$CONTAINER' 未运行"
    echo ""
    echo "可用的容器:"
    docker ps --format "  - {{.Names}}"
    exit 1
fi

# 获取容器 PID
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
if [ -z "$CONTAINER_PID" ] || [ "$CONTAINER_PID" = "0" ]; then
    print_error "无法获取容器 PID"
    exit 1
fi

# 获取容器网关 IP (用于白名单，允许 HTTP 响应回传)
# 注意：容器可能连接多个网络，需要用空格分隔多个网关
GATEWAYS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$CONTAINER" | xargs)
if [ -z "$GATEWAYS" ]; then
    print_error "无法获取容器网关 IP"
    exit 1
fi

echo "==========================================================================="
echo " net_filter - 网络动态拦截设置"
echo "==========================================================================="
echo ""
print_info "容器: $CONTAINER (PID: $CONTAINER_PID)"
print_info "网关: $GATEWAYS (白名单，允许 HTTP 响应)"
if [ -n "$WHITELIST_IPS" ]; then
    print_info "白名单 IP: $WHITELIST_IPS"
fi
echo ""

# ============================================================================
# cgroup 设置 (全局，幂等操作)
# ============================================================================

print_info "[1/2] 设置 cgroup..."

# 确保 net_cls 子系统已挂载
if [ ! -d "$CGROUP_BASE" ]; then
    mkdir -p $CGROUP_BASE
    mount -t cgroup -o net_cls net_cls $CGROUP_BASE
    echo "  挂载 net_cls cgroup"
fi

# 创建 cgroup 目录
mkdir -p $CGROUP_BASE/net_filter_external
mkdir -p $CGROUP_BASE/net_filter_internal

# 设置 classid
echo 0x100001 > $CGROUP_BASE/net_filter_external/net_cls.classid
echo 0x100002 > $CGROUP_BASE/net_filter_internal/net_cls.classid

# 启用子线程继承
echo 1 > $CGROUP_BASE/net_filter_external/cgroup.clone_children 2>/dev/null || true
echo 1 > $CGROUP_BASE/net_filter_internal/cgroup.clone_children 2>/dev/null || true

# 设置权限
chmod 666 $CGROUP_BASE/net_filter_external/tasks
chmod 666 $CGROUP_BASE/net_filter_internal/tasks
chmod 666 $CGROUP_BASE/tasks

print_success "cgroup 设置完成"
echo "    - $CGROUP_BASE/net_filter_external (classid=0x100001)"
echo "    - $CGROUP_BASE/net_filter_internal (classid=0x100002)"

# ============================================================================
# iptables 设置 (进入容器网络命名空间)
# ============================================================================

print_info "[2/2] 设置容器内 iptables..."

# 清理旧规则 (忽略不存在的规则)
# 清理网关白名单规则（可能有多个网关）
for gw in $GATEWAYS; do
    nsenter -t $CONTAINER_PID -n iptables -D OUTPUT -m cgroup --cgroup 0x100001 -d $gw -j ACCEPT 2>/dev/null || true
done

# 清理旧的白名单 IP 规则
if [ -n "$WHITELIST_IPS" ]; then
    IFS=',' read -ra WL_ARRAY <<< "$WHITELIST_IPS"
    for ip in "${WL_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # 去除空格
        [ -z "$ip" ] && continue
        nsenter -t $CONTAINER_PID -n iptables -D OUTPUT -m cgroup --cgroup 0x100001 -d "$ip" -j ACCEPT 2>/dev/null || true
    done
fi

for range in $INTERNAL_RANGES; do
    nsenter -t $CONTAINER_PID -n iptables -D OUTPUT -m cgroup --cgroup 0x100001 -d $range -j DROP 2>/dev/null || true
    nsenter -t $CONTAINER_PID -n iptables -D OUTPUT -m cgroup --cgroup 0x100002 -d $range -j ACCEPT 2>/dev/null || true
done
nsenter -t $CONTAINER_PID -n iptables -D OUTPUT -m cgroup --cgroup 0x100002 -j DROP 2>/dev/null || true

# external_only (0x100001): 拦截内网，但允许网关（HTTP 响应需要）
# 先添加网关白名单（必须在 DROP 规则之前，可能有多个网关）
for gw in $GATEWAYS; do
    nsenter -t $CONTAINER_PID -n iptables -A OUTPUT -m cgroup --cgroup 0x100001 -d $gw -j ACCEPT
    echo "    添加规则: ACCEPT cgroup 0x100001 -> $gw (网关白名单)"
done

# 添加用户指定的白名单 IP（在 DROP 规则之前）
if [ -n "$WHITELIST_IPS" ]; then
    IFS=',' read -ra WL_ARRAY <<< "$WHITELIST_IPS"
    for ip in "${WL_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # 去除空格
        [ -z "$ip" ] && continue
        nsenter -t $CONTAINER_PID -n iptables -A OUTPUT -m cgroup --cgroup 0x100001 -d "$ip" -j ACCEPT
        echo "    添加规则: ACCEPT cgroup 0x100001 -> $ip (用户白名单)"
    done
fi

for range in $INTERNAL_RANGES; do
    nsenter -t $CONTAINER_PID -n iptables -A OUTPUT -m cgroup --cgroup 0x100001 -d $range -j DROP
    echo "    添加规则: DROP cgroup 0x100001 -> $range"
done

# internal_only (0x100002): 只允许内网
for range in $INTERNAL_RANGES; do
    nsenter -t $CONTAINER_PID -n iptables -A OUTPUT -m cgroup --cgroup 0x100002 -d $range -j ACCEPT
    echo "    添加规则: ACCEPT cgroup 0x100002 -> $range"
done
nsenter -t $CONTAINER_PID -n iptables -A OUTPUT -m cgroup --cgroup 0x100002 -j DROP
echo "    添加规则: DROP cgroup 0x100002 -> 其他 (外网)"

print_success "iptables 规则设置完成"

# ============================================================================
# 验证
# ============================================================================

echo ""
print_info "验证 iptables 规则:"
# iptables 输出 classid 为十进制: 0x100001=1048577, 0x100002=1048578
nsenter -t $CONTAINER_PID -n iptables -L OUTPUT -n | grep -E "cgroup (1048577|1048578)" || echo "  (未找到规则)"

echo ""
echo "==========================================================================="
print_success "设置完成!"
echo "==========================================================================="
echo ""
echo "接下来:"
echo "  1. 确保容器挂载了 cgroup:"
echo "     volumes:"
echo "       - /sys/fs/cgroup:/sys/fs/cgroup:rw"
echo ""
echo "  2. 部署 net_filter 模块到容器:"
echo "     ./python/build.sh $CONTAINER"
echo "     ./php/build.sh $CONTAINER"
echo ""
echo "  3. 在代码中使用:"
echo "     Python: from net_filter import NetFilter"
echo "     PHP:    require_once 'net_filter.php';"
echo ""
