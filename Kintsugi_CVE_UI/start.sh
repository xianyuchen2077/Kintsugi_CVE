#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

for env_file in "$PACKAGE_ROOT/.env" "$SCRIPT_DIR/.env"; do
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
done

UI_ROOT="${UI_ROOT:-$SCRIPT_DIR}"
if [[ -z "${KINTSUGI_ROOT:-}" ]]; then
  if [[ -d "$SCRIPT_DIR/../kintsugi-dev" ]]; then
    KINTSUGI_ROOT="$(cd "$SCRIPT_DIR/../kintsugi-dev" && pwd)"
  elif [[ -d "$SCRIPT_DIR/../kintsugi-dev_origin" ]]; then
    KINTSUGI_ROOT="$(cd "$SCRIPT_DIR/../kintsugi-dev_origin" && pwd)"
  else
    KINTSUGI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)/kintsugi-dev"
  fi
fi
BRIDGE_HOST="${BRIDGE_HOST:-}"
BRIDGE_PORT="${BRIDGE_PORT:-8765}"
FRONTEND_HOST="${FRONTEND_HOST:-}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

COMMAND="${1:-start}"
ACCESS_MODE="${KINTSUGI_ACCESS_MODE:-local}"
case "$COMMAND" in
  token|remote)
    ACCESS_MODE="token"
    COMMAND="${2:-start}"
    ;;
  local)
    ACCESS_MODE="local"
    COMMAND="${2:-start}"
    ;;
esac

if [[ "$ACCESS_MODE" == "token" ]]; then
  BRIDGE_HOST="${BRIDGE_HOST:-0.0.0.0}"
  FRONTEND_HOST="${FRONTEND_HOST:-0.0.0.0}"
  KINTSUGI_BRIDGE_TOKEN="${KINTSUGI_BRIDGE_TOKEN:-}"
  if [[ -z "$KINTSUGI_BRIDGE_TOKEN" && "$COMMAND" != "status" && "$COMMAND" != "stop" && "$COMMAND" != "help" && "$COMMAND" != "-h" && "$COMMAND" != "--help" ]]; then
    printf 'ERROR: token mode requires KINTSUGI_BRIDGE_TOKEN. Create ../.env from ../.env.example and set it first.\n' >&2
    exit 1
  fi
else
  BRIDGE_HOST="${BRIDGE_HOST:-127.0.0.1}"
  FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
  KINTSUGI_BRIDGE_TOKEN=""
fi

# Set KINTSUGI_SUDO_PASSWORD before running if you want sudo automation.
# If it is empty, start.sh will ask once in an interactive shell and keep it
# only for this process tree.
SUDO_PASSWORD="${KINTSUGI_SUDO_PASSWORD:-}"

VENV_DIR="$KINTSUGI_ROOT/.venv"
DATA_DIR="$KINTSUGI_ROOT/data"
EBPF_LOG="$DATA_DIR/ebpf_loader.log"
BRIDGE_LOG="$DATA_DIR/bridge.log"
FRONTEND_LOG="$UI_ROOT/frontend.log"
EBPF_PID="$DATA_DIR/ebpf_loader.pid"
BRIDGE_PID="$DATA_DIR/bridge.pid"
FRONTEND_PID="$UI_ROOT/frontend.pid"
PREPARE_DIR="$DATA_DIR/.ui-prepared"

usage() {
  printf 'Usage: %s [local|token] [start|background|stop|restart|status]\n' "$0"
  printf '  local      no token, listen on 127.0.0.1 only (default)\n'
  printf '  token      token mode, listen on 0.0.0.0, requires KINTSUGI_BRIDGE_TOKEN\n'
  printf '  start      open eBPF, Bridge, and frontend in three terminal windows\n'
  printf '  background start them with nohup and write logs to files\n'
}

require_path() {
  local path="$1"
  local label="$2"
  if [[ ! -e "$path" ]]; then
    printf 'ERROR: %s not found: %s\n' "$label" "$path" >&2
    exit 1
  fi
}

activate_venv() {
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

is_port_busy() {
  local port="$1"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

quote() {
  printf '%q' "$1"
}

sudo_validate_command() {
  if [[ -n "$SUDO_PASSWORD" ]]; then
    printf 'printf %%s\\\\n %s | sudo -S -v' "$(quote "$SUDO_PASSWORD")"
  else
    printf 'sudo -v'
  fi
}

sudo_ebpf_command() {
  if [[ -n "$SUDO_PASSWORD" ]]; then
    printf 'printf %%s\\\\n %s | sudo -S -E /usr/bin/python3 syscall_filter/ebpf_load.py' "$(quote "$SUDO_PASSWORD")"
  else
    printf 'sudo -E /usr/bin/python3 syscall_filter/ebpf_load.py'
  fi
}

sudo_validate_now() {
  if [[ -n "$SUDO_PASSWORD" ]]; then
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -v
  else
    sudo -v
  fi
}

docker_compose_run() {
  local env_dir="$1"
  shift
  if (
    cd "$env_dir"
    docker compose "$@"
  ); then
    return
  fi
  if [[ -n "$SUDO_PASSWORD" ]]; then
    (
      cd "$env_dir"
      printf '%s\n' "$SUDO_PASSWORD" | sudo -S docker compose "$@"
    )
  else
    (
      cd "$env_dir"
      sudo docker compose "$@"
    )
  fi
}

file_hash() {
  sha256sum "$@" | sha256sum | awk '{print $1}'
}

prepare_flarum_40033() {
  local env_dir="$KINTSUGI_ROOT/cves/php/CVE-2023-40033/env"
  local stamp="$PREPARE_DIR/CVE-2023-40033.sha256"
  local current
  [[ -d "$env_dir" ]] || return
  mkdir -p "$PREPARE_DIR"
  current="$(file_hash "$env_dir/Dockerfile" "$env_dir/docker-compose.yml" "$env_dir/install.sh" "$env_dir/startup.sh")"
  if [[ -f "$stamp" && "$(cat "$stamp")" == "$current" ]]; then
    printf '[skip] CVE-2023-40033 image already prepared\n'
    return
  fi

  printf '[prepare] CVE-2023-40033 Flarum image\n'
  docker_compose_run "$env_dir" down -v --remove-orphans
  docker_compose_run "$env_dir" build flarum
  printf '%s\n' "$current" > "$stamp"
}

prepare_cve_images() {
  restore_php_tracer_configs
  prepare_flarum_40033
}

restore_php_tracer_configs() {
  local ini
  while IFS= read -r ini; do
    if grep -q '^tracer.enabled=0' "$ini"; then
      sed -i 's/^tracer.enabled=0$/tracer.enabled=1/' "$ini"
      printf '[prepare] enabled PHP tracer: %s\n' "${ini#$KINTSUGI_ROOT/}"
    fi
  done < <(find "$KINTSUGI_ROOT/cves/php" -path '*/env/99-tracer-filter.ini' -type f 2>/dev/null)
}

start_ebpf_now() {
  if [[ -n "$SUDO_PASSWORD" ]]; then
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -E /usr/bin/python3 syscall_filter/ebpf_load.py
  else
    sudo -E /usr/bin/python3 syscall_filter/ebpf_load.py
  fi
}

terminal_bin() {
  command -v gnome-terminal || command -v konsole || command -v xfce4-terminal || command -v xterm || true
}

pid_alive() {
  local file="$1"
  [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null
}

start_ebpf_background() {
  if pgrep -af 'syscall_filter/ebpf_load.py|ebpf_load.py' >/dev/null; then
    printf '[skip] eBPF loader already running\n'
    return
  fi

  printf '[start] eBPF loader\n'
  sudo_validate_now
  (
    cd "$KINTSUGI_ROOT"
    activate_venv
    nohup bash -lc "$(declare -f quote sudo_ebpf_command start_ebpf_now); SUDO_PASSWORD=$(quote "$SUDO_PASSWORD"); start_ebpf_now" > "$EBPF_LOG" 2>&1 &
    echo $! > "$EBPF_PID"
  )
  printf '        log: %s\n' "$EBPF_LOG"
}

start_bridge_background() {
  if is_port_busy "$BRIDGE_PORT"; then
    printf '[skip] Bridge port %s is already in use\n' "$BRIDGE_PORT"
    return
  fi

  printf '[start] Bridge http://%s:%s\n' "$BRIDGE_HOST" "$BRIDGE_PORT"
  (
    cd "$KINTSUGI_ROOT"
    activate_venv
    export KINTSUGI_BRIDGE_TOKEN
    export KINTSUGI_SUDO_PASSWORD="$SUDO_PASSWORD"
    nohup python -m uvicorn bridge.kintsugi_bridge:app --host "$BRIDGE_HOST" --port "$BRIDGE_PORT" > "$BRIDGE_LOG" 2>&1 &
    echo $! > "$BRIDGE_PID"
  )
  printf '        log: %s\n' "$BRIDGE_LOG"
}

start_frontend_background() {
  if is_port_busy "$FRONTEND_PORT"; then
    printf '[skip] Frontend port %s is already in use\n' "$FRONTEND_PORT"
    return
  fi

  printf '[start] Frontend http://localhost:%s\n' "$FRONTEND_PORT"
  (
    cd "$UI_ROOT"
    activate_venv
    nohup npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT" > "$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID"
  )
  printf '        log: %s\n' "$FRONTEND_LOG"
}

check_requirements() {
  require_path "$KINTSUGI_ROOT" "Kintsugi root"
  require_path "$UI_ROOT" "UI root"
  require_path "$VENV_DIR/bin/activate" "virtualenv"
  require_path "$KINTSUGI_ROOT/syscall_filter/ebpf_load.py" "eBPF loader"
  if [[ ! -f "$KINTSUGI_ROOT/bridge/kintsugi_bridge.py" ]]; then
    require_path "$UI_ROOT/bridge/kintsugi_bridge.py" "packaged Bridge"
    mkdir -p "$KINTSUGI_ROOT/bridge"
    cp -a "$UI_ROOT/bridge/." "$KINTSUGI_ROOT/bridge/"
    printf '[prepare] installed Bridge into %s\n' "$KINTSUGI_ROOT/bridge"
  fi
  require_path "$UI_ROOT/package.json" "UI package"
  mkdir -p "$DATA_DIR"
}

prompt_sudo_password() {
  if [[ -n "$SUDO_PASSWORD" || "$COMMAND" == "status" || "$COMMAND" == "stop" || "$COMMAND" == "help" || "$COMMAND" == "-h" || "$COMMAND" == "--help" ]]; then
    return
  fi
  if [[ -t 0 ]]; then
    read -rsp "sudo password for eBPF/Docker automation (press Enter to skip): " SUDO_PASSWORD
    printf '\n'
  fi
}

open_terminal() {
  local title="$1"
  local command="$2"
  local term
  term="$(terminal_bin)"
  if [[ -z "$term" ]]; then
    printf 'ERROR: no supported terminal found. Install gnome-terminal or run: %s background\n' "$0" >&2
    exit 1
  fi

  case "$(basename "$term")" in
    gnome-terminal)
      "$term" --title "$title" -- bash -lc "$command" &
      ;;
    konsole)
      "$term" --new-tab --workdir "$PWD" -p "tabtitle=$title" -e bash -lc "$command" &
      ;;
    xfce4-terminal)
      "$term" --title "$title" --command "bash -lc $(printf '%q' "$command")" &
      ;;
    xterm)
      "$term" -T "$title" -e bash -lc "$command" &
      ;;
    *)
      printf 'ERROR: unsupported terminal: %s\n' "$term" >&2
      exit 1
      ;;
  esac
}

hold_command() {
  local command="$1"
  printf '%s; code=$?; echo; echo "[exit] code=${code}. Press Enter to close."; read -r _; exit "$code"' "$command"
}

start_all() {
  check_requirements
  prepare_cve_images
  local kroot uroot venv
  kroot="$(quote "$KINTSUGI_ROOT")"
  uroot="$(quote "$UI_ROOT")"
  venv="$(quote "$VENV_DIR/bin/activate")"

  if ! pgrep -af 'syscall_filter/ebpf_load.py|ebpf_load.py' >/dev/null; then
    open_terminal "Kintsugi eBPF loader" "$(hold_command "cd $kroot && source $venv && $(sudo_validate_command) && $(sudo_ebpf_command)")"
  else
    printf '[skip] eBPF loader already running\n'
  fi

  if ! is_port_busy "$BRIDGE_PORT"; then
    open_terminal "Kintsugi Bridge :$BRIDGE_PORT" "$(hold_command "cd $kroot && source $venv && export KINTSUGI_BRIDGE_TOKEN=$(quote "$KINTSUGI_BRIDGE_TOKEN") && export KINTSUGI_SUDO_PASSWORD=$(quote "$SUDO_PASSWORD") && python -m uvicorn bridge.kintsugi_bridge:app --host $(quote "$BRIDGE_HOST") --port $(quote "$BRIDGE_PORT")")"
  else
    printf '[skip] Bridge port %s is already in use\n' "$BRIDGE_PORT"
  fi

  if ! is_port_busy "$FRONTEND_PORT"; then
    open_terminal "Kintsugi UI :$FRONTEND_PORT" "$(hold_command "cd $uroot && source $venv && npm run dev -- --host $(quote "$FRONTEND_HOST") --port $(quote "$FRONTEND_PORT")")"
  else
    printf '[skip] Frontend port %s is already in use\n' "$FRONTEND_PORT"
  fi

  printf '\nOpened terminal windows.\n'
  printf 'Mode:     %s\n' "$ACCESS_MODE"
  printf 'Bridge:   http://%s:%s\n' "$BRIDGE_HOST" "$BRIDGE_PORT"
  printf 'Frontend: http://%s:%s\n' "$FRONTEND_HOST" "$FRONTEND_PORT"
  if [[ "$ACCESS_MODE" == "token" ]]; then
    printf 'Token:    configured\n'
  fi
}

background_all() {
  check_requirements
  prepare_cve_images
  start_ebpf_background
  start_bridge_background
  start_frontend_background
  printf '\nDone.\n'
  printf 'Mode:     %s\n' "$ACCESS_MODE"
  printf 'Bridge:   http://%s:%s\n' "$BRIDGE_HOST" "$BRIDGE_PORT"
  printf 'Frontend: http://%s:%s\n' "$FRONTEND_HOST" "$FRONTEND_PORT"
  if [[ "$ACCESS_MODE" == "token" ]]; then
    printf 'Token:    configured\n'
  fi
}

stop_pid_file() {
  local file="$1"
  local label="$2"
  if pid_alive "$file"; then
    local pid
    pid="$(cat "$file")"
    printf '[stop] %s pid=%s\n' "$label" "$pid"
    kill "$pid" 2>/dev/null || true
  else
    printf '[skip] %s not running from pid file\n' "$label"
  fi
  rm -f "$file"
}

stop_all() {
  stop_pid_file "$FRONTEND_PID" "Frontend"
  stop_pid_file "$BRIDGE_PID" "Bridge"
  stop_pid_file "$EBPF_PID" "eBPF loader"
  pkill -f "$UI_ROOT/node_modules/.bin/vite" 2>/dev/null || true
  pkill -f "uvicorn bridge.kintsugi_bridge:app" 2>/dev/null || true
  pkill -f 'syscall_filter/ebpf_load.py|ebpf_load.py' 2>/dev/null || true
}

status_one() {
  local file="$1"
  local label="$2"
  if pid_alive "$file"; then
    printf '[ok]   %s pid=%s\n' "$label" "$(cat "$file")"
  else
    printf '[down] %s\n' "$label"
  fi
}

status_all() {
  if pgrep -af 'syscall_filter/ebpf_load.py|ebpf_load.py' >/dev/null; then
    printf '[ok]   eBPF loader\n'
  else
    printf '[down] eBPF loader\n'
  fi
  if is_port_busy "$BRIDGE_PORT"; then
    printf '[ok]   Bridge port %s\n' "$BRIDGE_PORT"
  else
    printf '[down] Bridge port %s\n' "$BRIDGE_PORT"
  fi
  if is_port_busy "$FRONTEND_PORT"; then
    printf '[ok]   Frontend port %s\n' "$FRONTEND_PORT"
  else
    printf '[down] Frontend port %s\n' "$FRONTEND_PORT"
  fi
  printf '\npid files:\n'
  status_one "$EBPF_PID" "eBPF pid file"
  status_one "$BRIDGE_PID" "Bridge pid file"
  status_one "$FRONTEND_PID" "Frontend pid file"
  printf '\nprocess scan:\n'
  pgrep -af 'syscall_filter/ebpf_load.py|uvicorn bridge.kintsugi_bridge|npm run dev|vite' || true
}

case "$COMMAND" in
  start) prompt_sudo_password; start_all ;;
  background) prompt_sudo_password; background_all ;;
  stop) stop_all ;;
  restart) stop_all; start_all ;;
  status) status_all ;;
  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
