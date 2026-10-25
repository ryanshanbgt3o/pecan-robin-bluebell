#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  # 取消和超时可能跳过后续步骤，因此在脚本退出时也主动注销。
  timeout 15s sudo tailscale logout >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 0' INT TERM HUP

export MNSJ_BIND_ADDRESS
MNSJ_BIND_ADDRESS="$(tailscale ip -4)"
python3 runner/control.py
