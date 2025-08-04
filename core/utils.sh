#!/usr/bin/env bash
# Shared helper functions for wetmonkey

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'

banner() {
  echo -e "${BLUE}================================================${NC}"
  echo -e "${GREEN}  (\\_/)      WetMonkey V0 - Network Anomaly Testing Toolkit${NC}"
  echo -e "${GREEN}  (oᴥo)      ${YELLOW}https://github.com/yourusername/wetmonkey${NC}"
  echo -e "${GREEN}  /   \\${NC}     ${MAGENTA}Type '0' to exit at any time${NC}"
  echo -e "${BLUE}================================================${NC}"
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This module requires root privileges.${NC}" >&2
    exit 2
  fi
}

log_json() {
  # Usage: log_json <event> <details>
  local event="$1"; shift || true
  local details="$*"
  local ts
  ts="$(date -u +%FT%TZ)"
  printf '{"time":"%s","event":"%s","details":"%s"}\n' "$ts" "$event" "$details"
}

clone_if_missing() {
  # clone_if_missing <git-url> <destination-dir>
  local url="$1" dest="$2"
  if [[ ! -d "$dest/.git" ]]; then
    echo "[+] Cloning $url -> $dest" >&2
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 "$url" "$dest"
  fi
}
