#!/usr/bin/env bash
# netmon installer — clone, build an isolated venv, install a `netmon` launcher,
# and (optionally) a hardened systemd recorder. Designed to be *read before run*:
#
#     curl -fsSLO https://git.disroot.org/afk/netmon/raw/branch/main/install.sh
#     less install.sh          # inspect it — never pipe a script you haven't read
#     sudo bash install.sh     # add --enable-service and/or --setcap as desired
#
# Flags:
#   --enable-service   install + enable + start the netmon.service background recorder
#   --setcap           grant CAP_NET_RAW to the private interpreter so the interactive
#                      TUI runs without a sudo prompt. The capability is scoped to the
#                      `netmon` group (the interpreter is chmod 0750 root:netmon), so
#                      only group members get passwordless capture — NOT every local
#                      user. Refused if it would land on a shared /usr python.
#   --uninstall        remove everything this script installs
#
# Security model: live capture needs CAP_NET_RAW. The background recorder gets it from
# systemd's AmbientCapabilities as a dedicated non-root user (no setcap, no root shell).
# The interactive `netmon run` re-execs under sudo on demand unless you opt into --setcap.
#
# Trust boundaries you accept by running this:
#   * If uv is absent it is bootstrapped via `curl https://astral.sh/uv/install.sh | sh`
#     as root, with no checksum — pre-install uv (apt/pipx) to skip that step.
#   * `netmon update` runs `git pull` + `uv sync` as root, so whoever controls the git
#     repo or its pinned dependency tree can reach root on every host that updates.
set -euo pipefail

# NETMON_REPO/NETMON_REF let a fork (or a pre-merge branch test) override the source and
# branch/tag; default to upstream main. Note `netmon update` always tracks origin main.
REPO_HTTPS="${NETMON_REPO:-https://git.disroot.org/afk/netmon.git}"
NETMON_REF="${NETMON_REF:-main}"
NETMON_DIR="${NETMON_PREFIX:-/opt/netmon}"
LAUNCHER="/usr/local/bin/netmon"
SERVICE="/etc/systemd/system/netmon.service"
LOG_DIR="/var/log/netmon"
SVC_USER="netmon"
VENV_PY="$NETMON_DIR/.venv/bin/python3"

die() { echo "netmon-install: $*" >&2; exit 1; }

validate_prefix() {
  # NETMON_DIR is spliced into a root-run heredoc and rm -rf'd on uninstall, so refuse
  # anything but a plain absolute path (no spaces, shell metacharacters, or `..`).
  case "$NETMON_DIR" in
    /) die "NETMON_PREFIX must not be /" ;;
    /*) : ;;
    *) die "NETMON_PREFIX must be an absolute path" ;;
  esac
  case "$NETMON_DIR" in
    *[!A-Za-z0-9/._-]* | *..*) die "NETMON_PREFIX has unsafe characters" ;;
  esac
}

require_linux() {
  [ "$(uname -s)" = "Linux" ] || die "netmon captures via AF_PACKET — Linux only"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run me with sudo (I create a system user, a unit, and $LOG_DIR)"
}

ensure_tools() {
  command -v git >/dev/null || die "git not found — install it first (apt install git)"
  if ! command -v uv >/dev/null; then
    echo "==> installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
  command -v uv >/dev/null || die "uv still not on PATH after install"
  # Make uv reachable for `netmon update` later, which runs under sudo's stripped PATH.
  [ -e /usr/local/bin/uv ] || ln -s "$(command -v uv)" /usr/local/bin/uv
}

clone_or_pull() {
  if [ -d "$NETMON_DIR/.git" ]; then
    echo "==> updating existing checkout in $NETMON_DIR ($NETMON_REF)"
    git -C "$NETMON_DIR" fetch --depth 1 origin "$NETMON_REF"
    git -C "$NETMON_DIR" checkout -B "$NETMON_REF" FETCH_HEAD
  else
    echo "==> cloning netmon into $NETMON_DIR ($NETMON_REF)"
    git clone --depth 1 --branch "$NETMON_REF" "$REPO_HTTPS" "$NETMON_DIR"
  fi
}

build_venv() {
  echo "==> building isolated venv (uv-managed private Python)"
  # Keep the managed interpreter under $NETMON_DIR (world-readable), NOT under /root,
  # so the unprivileged service user can exec it; and so --setcap targets a private
  # binary, never the shared /usr python.
  export UV_PYTHON_INSTALL_DIR="$NETMON_DIR/pythons"
  export UV_PYTHON_PREFERENCE=only-managed
  ( cd "$NETMON_DIR" && uv python install 3.13 && uv sync --extra tui --no-dev )
  # Code/venv is not secret (the sensitive data lives in $LOG_DIR), and the service user
  # must traverse+exec the interpreter. If --setcap is later applied, maybe_setcap
  # re-locks that one now-capability-bearing binary to root + the netmon group.
  chmod -R a+rX "$NETMON_DIR"
}

install_launcher() {
  echo "==> installing launcher at $LAUNCHER"
  # First line carries the (possibly overridden) install dir; the rest is literal so
  # $@/$1 reach the console script untouched.
  cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# netmon launcher. Execs the venv console script directly (absolute path, no uv at
# runtime, so root's PATH is irrelevant). Elevates only when the action truly needs it.
set -euo pipefail
DIR=$NETMON_DIR
EOF
  cat >> "$LAUNCHER" <<'EOF'
BIN="$DIR/.venv/bin/netmon"
PY="$DIR/.venv/bin/python3"

needs_root() {
  case "${1:-}" in update|service) return 0 ;; esac      # write install dir / drive systemctl
  for a in "$@"; do case "$a" in
    -h|--help|-r|--read|--read=*) return 1 ;;             # help + replay need no privilege
  esac; done
  # already armed via --setcap? then no sudo for live capture.
  getcap "$(readlink -f "$PY")" 2>/dev/null | grep -q cap_net_raw && return 1
  return 0
}

if [ "$(id -u)" -ne 0 ] && needs_root "$@"; then
  exec sudo "$BIN" "$@"
fi
exec "$BIN" "$@"
EOF
  chmod 0755 "$LAUNCHER"
}

install_service() {
  echo "==> creating $SVC_USER user, $LOG_DIR, and $SERVICE"
  id "$SVC_USER" >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 700 "$LOG_DIR"
  cat > "$SERVICE" <<EOF
[Unit]
Description=netmon passive network recorder
After=network.target

[Service]
User=$SVC_USER
ExecStart=$NETMON_DIR/.venv/bin/netmon run --headless --log -q -o $LOG_DIR --rotate-mb 256 --rotate-keep 4
Restart=on-failure
# Passive capture needs exactly one capability; grant it to this service only.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$LOG_DIR
# Defence-in-depth for a long-lived raw-socket process storing browsing history.
# AF_PACKET is the capture socket itself; AF_NETLINK backs glibc/scapy interface
# enumeration (the 60s local-address refresh); AF_UNIX is asyncio's own signal
# socketpair (asyncio.run creates it at startup); AF_INET/AF_INET6 back scapy's
# ioctl-based interface queries. @system-service includes ioctl and @network-io
# (verified on systemd 257). /proc/net stays readable under ProtectProc=invisible
# (it is /proc/self/net).
RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallArchitectures=native
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
PrivateDevices=yes
# Above the documented worst case (~100 MB of bounded tables + interpreter + the
# 50k-packet queue): reclaim pressure at High gives an operator-visible warning
# window; the hard Max kills a leak instead of the host swapping.
MemoryHigh=384M
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

maybe_setcap() {
  local target; target="$(readlink -f "$VENV_PY")"
  case "$target" in
    /usr/*) die "refusing --setcap: $target is a shared interpreter (would arm raw sockets host-wide)" ;;
  esac
  command -v setcap >/dev/null || die "setcap not found (apt install libcap2-bin)"
  getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
  echo "==> granting cap_net_raw to $target (scoped to the '$SVC_USER' group)"
  setcap cap_net_raw+eip "$target"
  # A file capability applies to ANY user who can execute the binary. build_venv left it
  # world-executable (a+rX) so the service user could reach it; now that it bears a real
  # capability, lock execution to root + the netmon group so it is NOT a host-wide
  # unauthenticated raw-capture primitive. getcap for non-members then fails -> the
  # launcher falls back to sudo for them, which is correct.
  chown "root:$SVC_USER" "$target"
  chmod 0750 "$target"
  getcap "$target"
  if [ -n "${SUDO_USER:-}" ]; then
    usermod -aG "$SVC_USER" "$SUDO_USER"
    echo "==> added '$SUDO_USER' to the '$SVC_USER' group — log out/in for passwordless capture"
  else
    echo "==> add interactive users to the '$SVC_USER' group for passwordless capture:"
    echo "    sudo usermod -aG $SVC_USER <user>"
  fi
}

do_install() {
  require_linux
  require_root
  validate_prefix
  local enable_service=0 want_setcap=0
  for a in "$@"; do case "$a" in
    --enable-service) enable_service=1 ;;
    --setcap) want_setcap=1 ;;
    *) die "unknown flag: $a" ;;
  esac; done

  ensure_tools
  clone_or_pull
  build_venv
  install_launcher
  install_service
  [ "$want_setcap" -eq 1 ] && maybe_setcap || true
  if [ "$enable_service" -eq 1 ]; then
    systemctl enable --now netmon.service
    echo "==> netmon.service enabled and started (logs in $LOG_DIR)"
  fi

  cat <<EOF

netmon installed.
  netmon run              live TUI (ephemeral)
  netmon run --log        live TUI + persist the JSONL record
  netmon update           pull latest + re-sync, restart the service if running
  netmon service status   background recorder (systemctl passthrough)

The background recorder unit is installed but not enabled.
  sudo systemctl enable --now netmon.service      # start always-on recording
For a passwordless interactive TUI: rerun with --setcap.
EOF
}

do_uninstall() {
  require_root
  validate_prefix
  # Never rm -rf something that isn't actually a netmon checkout — guards a stray
  # NETMON_PREFIX from nuking an unrelated directory.
  [ -f "$NETMON_DIR/netmon.py" ] || die "$NETMON_DIR is not a netmon install — refusing to remove it"
  echo "==> stopping and removing netmon.service"
  systemctl disable --now netmon.service 2>/dev/null || true
  rm -f "$SERVICE"; systemctl daemon-reload 2>/dev/null || true
  if [ -e "$VENV_PY" ] && getcap "$(readlink -f "$VENV_PY")" 2>/dev/null | grep -q cap_net_raw; then
    setcap -r "$(readlink -f "$VENV_PY")" || true
  fi
  rm -f "$LAUNCHER"
  rm -rf "$NETMON_DIR"
  echo "==> removed launcher, venv, and unit."
  echo "    Left in place (delete manually if wanted): $LOG_DIR and the '$SVC_USER' user."
}

case "${1:-}" in
  --uninstall) shift; do_uninstall "$@" ;;
  *) do_install "$@" ;;
esac
