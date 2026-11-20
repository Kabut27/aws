#!/usr/bin/env bash
# CloudFront Telegram Manager - installer
#   sudo bash install.sh                 # Docker mode (default); installs Docker if missing
#   sudo bash install.sh --token XXX     # non-interactive
#   sudo bash install.sh --no-docker     # systemd + venv mode
#   sudo bash install.sh --uninstall     # stop and remove service (data is kept)
# Safe to re-run: it is also the update command (git pull && sudo bash install.sh).
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$APP_DIR/.env"
DATA_DIR="$APP_DIR/data"
SERVICE="cfbot"
MODE="docker"; ACTION="install"; TOKEN="${BOT_TOKEN:-}"
ARGS=("$@")

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else G=; Y=; R=; D=; N=; fi
info() { printf '%s▸%s %s\n' "$D" "$N" "$*"; }
ok()   { printf '%s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✘ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
usage() { sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token)     TOKEN="${2:-}"; shift 2 ;;
    --no-docker) MODE="systemd"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "Chaguo isiyojulikana: $1 (tumia --help)" ;;
  esac
done

# ---------- privileges ----------
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "Endesha kama root (sudo haipo)."
  exec sudo -E bash "${BASH_SOURCE[0]}" ${ARGS[@]+"${ARGS[@]}"}
fi
[ "$(uname -s)" = "Linux" ] || die "Linux pekee inasaidiwa."

# ---------- helpers ----------
pm_install() {
  if   command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "$@"
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q "$@"
  elif command -v apk     >/dev/null 2>&1; then apk add --no-cache "$@"
  else return 1; fi
}
ensure_cmd() { command -v "$1" >/dev/null 2>&1 || { info "Nainstall $1..."; pm_install "${2:-$1}" >/dev/null || die "Imeshindwa kuinstall $1"; }; }

env_get() { [ -f "$ENV_FILE" ] || return 0; sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }
env_set() {
  touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
}
rand_key()  { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }   # valid Fernet key
rand_code() { head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

BOT_USER=""
check_token() {  # 0 = ok or unverifiable (network), 1 = rejected by Telegram
  local r; r="$(curl -sS --max-time 10 "https://api.telegram.org/bot$1/getMe" 2>/dev/null || true)"
  case "$r" in
    *'"ok":true'*) BOT_USER="$(printf '%s' "$r" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')"; return 0 ;;
    "") warn "Siwezi kufikia Telegram kuhakiki token; naendelea."; return 0 ;;
    *) return 1 ;;
  esac
}

# ---------- uninstall ----------
uninstall() {
  if [ -f "/etc/systemd/system/$SERVICE.service" ]; then
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$SERVICE.service"; systemctl daemon-reload
    ok "Service ya systemd imeondolewa"
  fi
  if command -v docker >/dev/null 2>&1 && [ -f "$APP_DIR/docker-compose.yml" ]; then
    (cd "$APP_DIR" && { docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true; })
    ok "Container imesimamishwa"
  fi
  ok "Imekamilika. Data bado ipo: $DATA_DIR (futa kwa mkono ukitaka)."
}
if [ "$ACTION" = "uninstall" ]; then uninstall; exit 0; fi

# ---------- configuration (token only) ----------
configure() {
  ensure_cmd curl
  local tok="${TOKEN:-$(env_get BOT_TOKEN)}" interactive=0
  [ -r /dev/tty ] && interactive=1
  while :; do
    if [ -z "$tok" ]; then
      [ "$interactive" = 1 ] || die "Weka token: sudo bash install.sh --token <TOKEN>"
      printf 'Bot token (kutoka @BotFather): ' >/dev/tty; IFS= read -r tok </dev/tty
    fi
    tok="${tok//[[:space:]]/}"
    if [[ "$tok" =~ ^[0-9]{6,}:[A-Za-z0-9_-]{30,}$ ]] && check_token "$tok"; then break; fi
    warn "Token si sahihi."
    { [ -n "$TOKEN" ] || [ "$interactive" = 0 ]; } && die "Token imekataliwa."
    tok=""
  done
  env_set BOT_TOKEN "$tok"
  [ -n "$(env_get SECRET_KEY)" ] || { env_set SECRET_KEY "$(rand_key)"; ok "SECRET_KEY imetengenezwa (usiipoteze: inalinda keys za AWS)"; }

  CLAIM=""
  if [ -s "$DATA_DIR/owners.json" ] && [ "$(cat "$DATA_DIR/owners.json")" != "[]" ]; then
    info "Bot ina mmiliki tayari."
  else
    [ -n "$(env_get CLAIM_CODE)" ] || env_set CLAIM_CODE "$(rand_code)"
    CLAIM="$(env_get CLAIM_CODE)"
  fi
  ok "Config imehifadhiwa: $ENV_FILE (chmod 600)"
}

# ---------- docker mode ----------
DC="docker compose"
install_docker() {
  if command -v docker >/dev/null 2>&1; then
    ok "Docker ipo ($(docker --version | cut -d, -f1))"
  else
    info "Docker haipo, nainstall (get.docker.com)..."
    ensure_cmd curl
    local tmp; tmp="$(mktemp)"
    curl -fsSL https://get.docker.com -o "$tmp" || die "Imeshindwa kupakua installer ya Docker"
    sh "$tmp" >/dev/null || die "Installation ya Docker imeshindwa"
    rm -f "$tmp"; ok "Docker imewekwa"
  fi
  if ! docker info >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
    docker info >/dev/null 2>&1 || die "Docker daemon haiwaki. Angalia: systemctl status docker"
  fi
  if docker compose version >/dev/null 2>&1; then DC="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
  else
    info "Nainstall docker compose plugin..."
    pm_install docker-compose-plugin >/dev/null 2>&1 || true
    docker compose version >/dev/null 2>&1 || die "docker compose haipo. Install 'docker-compose-plugin' kwa mkono."
    DC="docker compose"
  fi
}

deploy_docker() {
  install_docker
  mkdir -p "$DATA_DIR"; chown -R 1000:1000 "$DATA_DIR"; chmod 700 "$DATA_DIR"
  info "Najenga na kuwasha container..."
  (cd "$APP_DIR" && $DC up -d --build) || die "docker compose imeshindwa"
  sleep 4
  if [ "$(docker inspect -f '{{.State.Running}}' "$SERVICE" 2>/dev/null)" != "true" ]; then
    (cd "$APP_DIR" && $DC logs --tail 30) || true
    die "Container haiendeshi. Angalia logs hapo juu."
  fi
  ok "Bot inaendesha (docker)"
  MANAGE="cd $APP_DIR && $DC logs -f        # logs
cd $APP_DIR && $DC restart       # restart"
}

# ---------- systemd mode ----------
deploy_systemd() {
  case "$APP_DIR" in /root|/root/*|/home/*) die "Mode ya systemd: hamisha repo hadi /opt (mfano: mv $APP_DIR /opt/cfbot) kisha endesha tena." ;; esac
  command -v systemctl >/dev/null 2>&1 || die "systemd haipo. Tumia mode ya Docker."
  if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
    info "Nainstall python3 + venv..."
    pm_install python3 python3-venv python3-pip >/dev/null || die "Install python3-venv kwa mkono."
  fi
  id "$SERVICE" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE"
  [ -x "$APP_DIR/venv/bin/python" ] || python3 -m venv "$APP_DIR/venv"
  info "Nainstall dependencies..."
  "$APP_DIR/venv/bin/pip" install -q --upgrade pip
  "$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  mkdir -p "$DATA_DIR"; chown -R "$SERVICE:$SERVICE" "$DATA_DIR"; chmod 700 "$DATA_DIR"
  chown root:"$SERVICE" "$ENV_FILE"; chmod 640 "$ENV_FILE"
  cat > "/etc/systemd/system/$SERVICE.service" << UNIT
[Unit]
Description=CloudFront Telegram Manager
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE
WorkingDirectory=$APP_DIR/src
EnvironmentFile=$ENV_FILE
Environment=DATA_DIR=$DATA_DIR
ExecStart=$APP_DIR/venv/bin/python run.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
  systemctl restart "$SERVICE"; sleep 3
  systemctl is-active --quiet "$SERVICE" || { journalctl -u "$SERVICE" -n 30 --no-pager || true; die "Service haiendeshi."; }
  ok "Bot inaendesha (systemd)"
  MANAGE="journalctl -u $SERVICE -f        # logs
systemctl restart $SERVICE      # restart"
}

# ---------- run ----------
MANAGE=""
echo; info "CloudFront Telegram Manager · mode: $MODE"
configure
if [ "$MODE" = "docker" ]; then deploy_docker; else deploy_systemd; fi

echo
ok "Imekamilika!"
[ -n "$BOT_USER" ] && echo "   Bot: https://t.me/$BOT_USER"
if [ -n "$CLAIM" ]; then
  echo "   Fungua bot kisha tuma:  /start $CLAIM"
  echo "   (code inatumika mara moja; wa kwanza kuitumia ndiye mmiliki)"
fi
echo
echo "$MANAGE" | sed 's/^/   /'
echo "   sudo bash install.sh --uninstall   # ondoa"
