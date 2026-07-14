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
#   --pip              build the venv from the system python3 + the checked-in, hash-pinned
#                      requirements.txt, and never fetch a toolchain. Use this to refuse the
#                      uv bootstrap's trust boundary outright.
#   --uninstall        remove everything this script installs
#
# Security model: live capture needs CAP_NET_RAW. The background recorder gets it from
# systemd's AmbientCapabilities as a dedicated non-root user (no setcap, no root shell).
# The interactive `netmon run` re-execs under sudo on demand unless you opt into --setcap.
#
# Trust boundaries you accept by running this:
#   * uv is used when it is already present, and the system python3 when it is not. The
#     `curl https://astral.sh/uv/install.sh | sh` bootstrap — as root, with no checksum — is
#     now the LAST resort, taken only when the host has no Python new enough to run netmon,
#     since only uv can then provide one. `--pip` refuses it outright.
#   * `netmon update` runs `git pull` + a rebuild as root, so whoever controls the git repo
#     or its pinned dependency tree can reach root on every host that updates.
set -euo pipefail

# Must equal requires-python in pyproject.toml — tests/test_packaging.py asserts it. netmon
# will not run below this, and the installer's whole job here is to say so early and clearly
# rather than hand someone a venv that dies with a SyntaxError three steps later.
PY_MIN=3.13

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

ensure_git() {
  command -v git >/dev/null || die "git not found — install it first (apt install git)"
}

py_ok() {
  # Usable means: new enough to run netmon, AND able to build a venv with pip in it. Debian
  # ships venv/ensurepip in a separate python3-venv package, so a host can have a perfectly
  # new interpreter that cannot seed a venv — check that here, not three steps later when
  # `python -m venv` fails with "No module named pip".
  "$1" -c "import sys, venv, ensurepip
sys.exit(0 if sys.version_info >= tuple(int(p) for p in '$PY_MIN'.split('.')) else 1)" \
    2>/dev/null
}

find_python() {
  local candidate path
  for candidate in "python$PY_MIN" python3 python3.14; do
    path="$(command -v "$candidate" 2>/dev/null)" || continue
    if py_ok "$path"; then echo "$path"; return 0; fi
  done
  return 1
}

py_report() {
  # What we found, so the failure names the host's actual state instead of a generic demand.
  local candidate path version
  for candidate in "python$PY_MIN" python3; do
    if path="$(command -v "$candidate" 2>/dev/null)"; then
      version="$("$path" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo '?')"
      if py_ok "$path"; then echo "    $candidate -> $version (usable)"
      elif "$path" -c 'import venv, ensurepip' 2>/dev/null; then echo "    $candidate -> $version (too old; need >= $PY_MIN)"
      else echo "    $candidate -> $version (no venv/ensurepip module — apt install python3-venv)"
      fi
    else
      echo "    $candidate -> not installed"
    fi
  done
  command -v uv >/dev/null && echo "    uv -> $(uv --version)" || echo "    uv -> not installed"
}

# select_builder sets these. It must assign globals rather than echo a result: $(...) runs in
# a subshell, so an echoed SYS_PY would be lost the moment the subshell exits.
BUILDER=""
SYS_PY=""

select_builder() {
  local want_pip="$1"

  if [ "$want_pip" -eq 1 ]; then
    SYS_PY="$(find_python)" || die "$(printf '%s\n%s\n%s\n' \
      "--pip needs a system Python >= $PY_MIN that can build a venv, and there is none." \
      "Found:" "$(py_report)")"
    BUILDER=pip
    return
  fi

  # uv already here: today's path, untouched — including every host a previous install.sh
  # bootstrapped (it symlinks /usr/local/bin/uv).
  if command -v uv >/dev/null; then BUILDER=uv; return; fi

  # No uv, but the host can already run netmon. Use what is here rather than piping an
  # unchecksummed installer into a root shell to obtain a second copy of it.
  if SYS_PY="$(find_python)"; then BUILDER=pip; return; fi

  # No uv and nothing new enough. Only uv can *provide* an interpreter, so this is the one
  # case where the bootstrap is genuinely the sole option rather than a default.
  if command -v curl >/dev/null; then BUILDER=uv; return; fi

  die "$(printf '%s\n%s\n%s\n%s\n' \
    "no usable Python, no uv, and no curl to fetch one. netmon needs Python >= $PY_MIN." \
    "Found:" "$(py_report)" \
    "  Install a system Python and re-run with --pip:
      apt install python$PY_MIN python$PY_MIN-venv
  ...or install uv, which provisions a private $PY_MIN under $NETMON_DIR/pythons:
      apt install uv        # Debian 13+ / Ubuntu 24.10+
      pipx install uv")"
}

ensure_uv() {
  if ! command -v uv >/dev/null; then
    # Guard the fetch itself: without this, a host with no curl dies on `set -e` with a bare
    # "curl: command not found" instead of a message that says what netmon actually needs.
    command -v curl >/dev/null || die "curl not found, and it is needed to bootstrap uv"
    echo "==> installing uv (unchecksummed download from astral.sh — see the header)"
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

build_venv_uv() {
  echo "==> building isolated venv (uv-managed private Python)"
  # Keep the managed interpreter under $NETMON_DIR (world-readable), NOT under /root,
  # so the unprivileged service user can exec it; and so --setcap targets a private
  # binary, never the shared /usr python.
  export UV_PYTHON_INSTALL_DIR="$NETMON_DIR/pythons"
  export UV_PYTHON_PREFERENCE=only-managed
  ( cd "$NETMON_DIR" && uv python install "$PY_MIN" && uv sync --extra tui --no-dev )
  # Code/venv is not secret (the sensitive data lives in $LOG_DIR), and the service user
  # must traverse+exec the interpreter. If --setcap is later applied, maybe_setcap
  # re-locks that one now-capability-bearing binary to root + the netmon group.
  chmod -R a+rX "$NETMON_DIR"
}

build_venv_pip() {
  local py="$1"
  echo "==> building isolated venv (system $("$py" -V 2>&1), pip + requirements.txt)"
  [ -f "$NETMON_DIR/requirements.txt" ] || die "requirements.txt missing from this checkout"
  # Reuse a venv this path built (so a --setcap grant on its interpreter survives an
  # upgrade); replace one the other builder made. A uv venv has no pip in it — the same
  # discriminator `netmon update` uses, and it needs no marker file to stay honest.
  if [ -d "$NETMON_DIR/.venv" ] && [ ! -x "$NETMON_DIR/.venv/bin/pip" ]; then
    rm -rf "$NETMON_DIR/.venv"
  fi
  # --copies, not the default symlink. A symlinked venv's bin/python3 resolves (readlink -f)
  # out to /usr/bin/python3.x, and setcap on THAT would arm raw sockets for every venv on the
  # host — maybe_setcap refuses it, correctly, which would silently cost this path its
  # passwordless TUI. The copy keeps the capability scoped to netmon's own interpreter,
  # exactly as the uv-managed one is. Only the launcher binary is copied; the stdlib still
  # comes from /usr via pyvenv.cfg, so distro security updates still land.
  [ -d "$NETMON_DIR/.venv" ] || "$py" -m venv --copies "$NETMON_DIR/.venv" \
    || die "python -m venv failed — install the venv module (apt install python3-venv)"
  # Hash-pinned and fully transitive, exported from uv.lock: pip installs nothing that is not
  # listed and nothing whose sha256 does not match — the same integrity guarantee uv sync
  # gives, which is the point for whoever took this path to avoid an unchecked download.
  "$VENV_PY" -m pip install --quiet --disable-pip-version-check --require-hashes \
      -r "$NETMON_DIR/requirements.txt" || die "dependency install failed"
  # The project itself, editable: the launcher and the unit exec $NETMON_DIR/.venv/bin/netmon,
  # and `netmon update`'s git pull must take effect without a reinstall. Build isolation
  # fetches the build backend from PyPI unhashed — uv sync does exactly the same (hatchling is
  # not in uv.lock), so this is parity, not a new trust boundary.
  "$VENV_PY" -m pip install --quiet --disable-pip-version-check --no-deps -e "$NETMON_DIR" \
      || die "netmon install failed"
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

# libcap2-bin installs getcap into /usr/sbin, and Debian does not put /usr/sbin on an
# unprivileged user's PATH — so a bare `getcap` call fails for exactly the user this check
# exists to serve. The failure was silent (2>/dev/null ate "command not found", grep matched
# nothing) and indistinguishable from "no capability", so --setcap appeared to do nothing:
# the interpreter was armed and the launcher sudo-prompted anyway. Look in the sbin dirs.
find_getcap() { PATH="/usr/sbin:/sbin:$PATH" command -v getcap 2>/dev/null; }

needs_root() {
  case "${1:-}" in update|service) return 0 ;; esac      # write install dir / drive systemctl
  for a in "$@"; do case "$a" in
    -h|--help|-r|--read|--read=*) return 1 ;;             # help + replay need no privilege
  esac; done
  # already armed via --setcap? then no sudo for live capture.
  gc="$(find_getcap)" || return 0                         # no getcap => cannot prove it; sudo
  "$gc" "$(readlink -f "$PY")" 2>/dev/null | grep -q cap_net_raw && return 1
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
  # Allowlist, not a /usr/* blocklist: the invariant is "the capability lands on a binary we
  # own", and that stays true however the venv was built, whereas a blocklist only names the
  # one wrong place we happened to think of. NETMON_DIR is already validated by
  # validate_prefix, so it holds no spaces or shell metacharacters.
  case "$target" in
    "$NETMON_DIR"/*) : ;;
    *) die "refusing --setcap: $target is outside $NETMON_DIR — a shared interpreter (would arm raw sockets host-wide)" ;;
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
  # A file capability puts the loader into secure-execution mode (AT_SECURE): $ORIGIN rpaths
  # and LD_LIBRARY_PATH are ignored, so an interpreter that finds its libpython that way stops
  # starting the moment it is armed. Prove it still runs, or hand the capability back — a
  # broken netmon is worse than one that asks for sudo.
  if ! "$VENV_PY" -c pass 2>/dev/null; then
    setcap -r "$target" || true
    die "the armed interpreter will not start (secure-execution mode); capability revoked"
  fi
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
  local enable_service=0 want_setcap=0 want_pip=0
  for a in "$@"; do case "$a" in
    --enable-service) enable_service=1 ;;
    --setcap) want_setcap=1 ;;
    --pip) want_pip=1 ;;
    *) die "unknown flag: $a" ;;
  esac; done

  ensure_git
  # The clone comes before the builder runs: the pip path installs from the checkout's own
  # requirements.txt, so the tree has to be on disk before we can build against it.
  clone_or_pull
  select_builder "$want_pip"
  if [ "$BUILDER" = pip ]; then
    build_venv_pip "$SYS_PY"
  else
    ensure_uv
    build_venv_uv
  fi
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
