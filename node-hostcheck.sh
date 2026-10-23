#!/usr/bin/env bash
#
# node-hostcheck — read-only host check for the Node.js October 2026
# security release (CVE-2026-111497 Brotli RCE, TLS hostname bypasses,
# and 8 more), plus the eMudhra CA distrust.
#
# Servers often have several Node.js installs: the system package, nvm /
# fnm / volta / asdf / n / nodenv versions in user homes, snap, the copy
# bundled with VS Code Server, and whatever a PM2 or systemd service
# actually starts. This script finds them, compares each against the
# fixed releases, and checks which version every RUNNING Node process
# is really using — including processes still running a binary that has
# since been replaced (restart needed).
#
# READ-ONLY: it never changes files, settings or services and sends no
# network traffic. (--containers runs `node --version` inside running
# Docker containers and nothing else.) Indicator check, not a guarantee.
#
# MIT License — https://github.com/Charlie-Netdevops/node-hostcheck

TOOL_VERSION="0.1.0"
DATA_DATE="2026-10-22"

# Fixed releases (Node.js security release, 21 Oct 2026). Supported lines
# are the even majors below; anything older, and odd majors, are EOL.
declare -A FIXED=( [22]="22.23.4" [24]="24.22.1" [26]="26.12.1" )
CVES="CVE-2026-111497|CVE-2026-105482|CVE-2026-105483|CVE-2026-106069|CVE-2026-105481|CVE-2026-106072|CVE-2026-106074|CVE-2026-106070|CVE-2026-106071|CVE-2026-106073"

# ---------------------------------------------------------------- options ---

OUT_JSON=0
DO_CONTAINERS=0
SEARCH_DIRS=()
USE_COLOR=auto

usage() {
  cat <<EOF
node-hostcheck $TOOL_VERSION — read-only check for the Node.js October 2026
security release (CVE-2026-111497 and 9 more) on this host.

Usage: sudo ./node-hostcheck.sh [options]

Options:
  --json            Machine-readable JSON output (for n8n, cron, SIEM)
  --containers      Also run 'node --version' inside running Docker containers
  --search DIR      Extra directory to search for node binaries (repeatable),
                    e.g. /srv or /opt/apps for app-bundled runtimes
  --no-color        Disable colours
  -V, --version     Show version
  -h, --help        Show this help

Exit codes:
  0  every Node.js found (installed and running) is patched
  1  vulnerable: unpatched/EOL Node installed or running, or restart needed
  2  needs attention: unknown versions, EOL with backport, CA bundle issues
  3  no Node.js found
 64  bad arguments

Run as root for full results (all users' installs and processes).
Only run it on systems you own or are authorised to check.
EOF
}

die() { echo "error: $*" >&2; exit 64; }

while [ $# -gt 0 ]; do
  case "$1" in
    --json) OUT_JSON=1 ;;
    --containers) DO_CONTAINERS=1 ;;
    --search)
      [ -n "${2:-}" ] || die "--search needs a directory"
      [ -d "$2" ] || die "--search: '$2' is not a directory"
      SEARCH_DIRS+=("$2"); shift ;;
    --no-color) USE_COLOR=0 ;;
    -V|--version) echo "node-hostcheck $TOOL_VERSION (data $DATA_DATE)"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; echo >&2; usage >&2; exit 64 ;;
  esac
  shift
done

# ---------------------------------------------------------------- helpers ---

have() { command -v "$1" >/dev/null 2>&1; }
if have timeout; then T() { timeout 10 "$@"; }; else T() { "$@"; }; fi

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

if [ "$USE_COLOR" = auto ]; then
  if [ -t 1 ] && [ "$OUT_JSON" -eq 0 ]; then USE_COLOR=1; else USE_COLOR=0; fi
fi
if [ "$USE_COLOR" -eq 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLD=""; DIM=""; RST=""
fi

json_esc() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}
  printf '%s' "$s"
}

NOTES=()
note() { NOTES+=("$1"); }

F_SEV=(); F_TITLE=(); F_DETAIL=()
finding() { F_SEV+=("$1"); F_TITLE+=("$2"); F_DETAIL+=("$3"); }

# Compare dotted versions: returns 0 if $1 >= $2
ver_ge() {
  local -a a b
  local i
  IFS=. read -ra a <<< "$1"
  IFS=. read -ra b <<< "$2"
  for i in 0 1 2; do
    local x=${a[$i]:-0} y=${b[$i]:-0}
    [ "$x" -gt "$y" ] && return 0
    [ "$x" -lt "$y" ] && return 1
  done
  return 0
}

shopt -s nullglob

# -------------------------------------------------------------- discovery ---

declare -A SEEN
B_PATH=(); B_SRC=()

add_bin() { # path source
  local p=$1 r
  [ -f "$p" ] && [ -x "$p" ] || return
  r=$(readlink -f "$p" 2>/dev/null || echo "$p")
  [ -n "${SEEN[$r]:-}" ] && return
  SEEN[$r]=1
  B_PATH+=("$r"); B_SRC+=("$2")
}

HOMES=(/root /home/*)

discover() {
  local p h
  for p in $(type -ap node nodejs 2>/dev/null); do add_bin "$p" path; done
  for p in /usr/bin/node /usr/bin/nodejs /usr/local/bin/node /usr/bin/node[0-9]* \
      /usr/local/lib/nodejs/*/bin/node /opt/node*/bin/node /opt/*/bin/node \
      /usr/local/n/versions/node/*/bin/node /usr/local/nvm/versions/node/*/bin/node \
      /opt/nvm/versions/node/*/bin/node /snap/node/current/bin/node \
      /usr/lib/code-server/lib/node; do
    add_bin "$p" system
  done
  for h in "${HOMES[@]}"; do
    [ -d "$h" ] || continue
    for p in "$h"/.nvm/versions/node/*/bin/node; do add_bin "$p" nvm; done
    for p in "$h"/.local/share/fnm/node-versions/*/installation/bin/node \
        "$h"/.fnm/node-versions/*/installation/bin/node; do add_bin "$p" fnm; done
    for p in "$h"/.volta/tools/image/node/*/bin/node; do add_bin "$p" volta; done
    for p in "$h"/.asdf/installs/nodejs/*/bin/node; do add_bin "$p" asdf; done
    for p in "$h"/.nodenv/versions/*/bin/node; do add_bin "$p" nodenv; done
    for p in "$h"/.n/bin/node "$h"/n/bin/node; do add_bin "$p" n; done
    for p in "$h"/.vscode-server/bin/*/node "$h"/.vscode-server/cli/servers/*/server/node \
        "$h"/.cursor-server/bin/*/node "$h"/.cursor-server/cli/servers/*/server/node \
        "$h"/.local/share/code-server/*/lib/node; do add_bin "$p" "editor-server"; done
  done
  local d
  for d in "${SEARCH_DIRS[@]}"; do
    while IFS= read -r p; do add_bin "$p" search; done \
      < <(find "$d" -xdev -maxdepth 8 -type f \( -name node -o -name nodejs \) -perm -u+x 2>/dev/null)
  done
  [ "$IS_ROOT" -eq 0 ] && note "Not running as root: other users' home folders (nvm, fnm, volta...) may not have been searched."
}

# -------------------------------------------------------- version + status ---

pkg_owner() {
  if have dpkg-query; then
    dpkg-query -S "$1" 2>/dev/null | head -n1 | cut -d: -f1
  elif have rpm; then
    rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n1
  fi
}

pkg_version() {
  if have dpkg-query; then
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null
  elif have rpm; then
    rpm -q --qf '%{VERSION}' "$1" 2>/dev/null
  fi
}

# Read the version WITHOUT executing the binary where possible.
# Order: node_version.h next to the install -> package metadata ->
# version in the install path -> run --version (as the file's owner).
VSRC=""
get_version() { # path pkg
  local path=$1 pkg=$2 v="" dir hdr owner
  VSRC=""; GV_VER=""
  dir=$(dirname "$path")
  for hdr in "$dir/../include/node/node_version.h" "$dir/../../include/node/node_version.h"; do
    if [ -f "$hdr" ]; then
      v=$(awk '/^#define NODE_MAJOR_VERSION/{a=$3} /^#define NODE_MINOR_VERSION/{b=$3} /^#define NODE_PATCH_VERSION/{c=$3} END{if(a!="")print a"."b"."c}' "$hdr" 2>/dev/null)
      [ -n "$v" ] && { VSRC=header; GV_VER=$v; return; }
    fi
  done
  if [ -n "$pkg" ]; then
    v=$(pkg_version "$pkg" | sed 's/^[0-9]*://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    [ -n "$v" ] && { VSRC=package; GV_VER=$v; return; }
  fi
  v=$(printf '%s' "$path" | grep -oE '/v?[0-9]+\.[0-9]+\.[0-9]+/' | tail -n1 | tr -d '/v')
  [ -n "$v" ] && { VSRC=path; GV_VER=$v; return; }
  owner=$(stat -c %U "$path" 2>/dev/null)
  if [ "$IS_ROOT" -eq 1 ] && [ -n "$owner" ] && [ "$owner" != root ]; then
    if have runuser; then
      v=$(T runuser -u "$owner" -- "$path" --version 2>/dev/null | head -n1)
    elif have setpriv; then
      v=$(T setpriv --reuid="$owner" --regid="$(id -g "$owner")" --clear-groups "$path" --version 2>/dev/null | head -n1)
    fi
  else
    v=$(T "$path" --version 2>/dev/null | head -n1)
  fi
  v=$(printf '%s' "$v" | grep -oE '^v?[0-9]+\.[0-9]+\.[0-9]+' | tr -d v)
  [ -n "$v" ] && VSRC="exec"
  GV_VER=$v
}

CHANGELOG_FOUND=0
backported() { # pkg
  local pkg=$1 f
  CHANGELOG_FOUND=0
  [ -z "$pkg" ] && return 1
  if ! have dpkg-query && have rpm; then
    local cl
    cl=$(rpm -q --changelog "$pkg" 2>/dev/null)
    [ -n "$cl" ] && CHANGELOG_FOUND=1
    printf '%s\n' "$cl" | grep -qE "$CVES" && return 0
    return 1
  fi
  for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
    [ -f "$f" ] || continue
    CHANGELOG_FOUND=1
    zgrep -qE "$CVES" "$f" 2>/dev/null && return 0
  done
  return 1
}

classify() { # version pkg -> C_STATUS C_NOTE
  local v=$1 pkg=$2 major fixed
  C_STATUS=UNKNOWN; C_NOTE=""
  if [ -z "$v" ]; then
    C_NOTE="could not read the version safely — check it by hand (node --version)"
    return
  fi
  major=${v%%.*}
  fixed=${FIXED[$major]:-}
  if [ -n "$fixed" ]; then
    if ver_ge "$v" "$fixed"; then
      C_STATUS=PATCHED; C_NOTE="at or above the fixed release $fixed"; return
    fi
    if backported "$pkg"; then
      C_STATUS=PATCHED_BACKPORT; C_NOTE="distro package $pkg lists the CVE fixes (backport)"; return
    fi
    C_STATUS=VULNERABLE; C_NOTE="update to $fixed or newer, then restart every process using it"
    [ "$CHANGELOG_FOUND" -eq 0 ] && [ -n "$pkg" ] && C_NOTE="$C_NOTE (no distro changelog found to check for a backport)"
    return
  fi
  if [ "$major" -lt 22 ] || { [ $((major % 2)) -eq 1 ] && [ "$major" -lt 27 ]; }; then
    if backported "$pkg"; then
      C_STATUS=EOL_BACKPORT; C_NOTE="distro backport found, but Node $major is end-of-life — move to 24 or 26"
      return
    fi
    C_STATUS=EOL; C_NOTE="end-of-life (Node $major) — no fix; move to Node 24 or 26 LTS"
    return
  fi
  C_NOTE="Node $major is not in this tool's data ($DATA_DATE) — check nodejs.org"
}

R_PATH=(); R_SRC=(); R_VER=(); R_VSRC=(); R_PKG=(); R_STATUS=(); R_NOTE=()
declare -A STATUS_OF VER_OF

check_one() { # path source
  local path=$1 src=$2 pkg ver
  pkg=$(pkg_owner "$path")
  get_version "$path" "$pkg"; ver=$GV_VER
  classify "$ver" "$pkg"
  R_PATH+=("$path"); R_SRC+=("$src"); R_VER+=("$ver"); R_VSRC+=("$VSRC"); R_PKG+=("$pkg")
  R_STATUS+=("$C_STATUS"); R_NOTE+=("$C_NOTE")
  STATUS_OF[$path]=$C_STATUS; VER_OF[$path]=$ver
}

check_installs() {
  local i
  for i in "${!B_PATH[@]}"; do check_one "${B_PATH[$i]}" "${B_SRC[$i]}"; done
}

# ------------------------------------------------------- running processes ---

P_PID=(); P_USER=(); P_EXE=(); P_VER=(); P_STATUS=(); P_CMD=()
EXTRA_CA=()
declare -A EXTRA_CA_SEEN
OS_STORE_PROCS=()

check_processes() {
  local d pid exe base user cmd st ver env_ca opts
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    base=$(basename "${exe% (deleted)}")
    case "$base" in node|nodejs|node[0-9]*) ;; *) continue ;; esac
    user=$(stat -c %U "$d" 2>/dev/null)
    cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | cut -c1-120)
    if [ "${exe% (deleted)}" != "$exe" ]; then
      st=RESTART_NEEDED; ver=""
    else
      if [ -z "${STATUS_OF[$exe]:-}" ]; then
        add_bin "$exe" process
        check_one "$exe" process
      fi
      st=${STATUS_OF[$exe]}; ver=${VER_OF[$exe]}
    fi
    P_PID+=("$pid"); P_USER+=("$user"); P_EXE+=("${exe% (deleted)}"); P_VER+=("$ver"); P_STATUS+=("$st"); P_CMD+=("$cmd")

    # CA settings of this process (needs root for other users' processes)
    if [ -r "$d/environ" ]; then
      env_ca=$(tr '\0' '\n' < "$d/environ" 2>/dev/null | sed -n 's/^NODE_EXTRA_CA_CERTS=//p' | head -n1)
      if [ -n "$env_ca" ] && [ -z "${EXTRA_CA_SEEN[$env_ca]:-}" ]; then
        EXTRA_CA_SEEN[$env_ca]=1; EXTRA_CA+=("$env_ca")
      fi
      opts=$(tr '\0' '\n' < "$d/environ" 2>/dev/null | sed -n 's/^NODE_OPTIONS=//p' | head -n1)
    else
      opts=""
    fi
    case "$cmd $opts" in
      *--use-openssl-ca*|*--use-system-ca*) OS_STORE_PROCS+=("PID $pid ($user)") ;;
    esac
  done

  local i stale=() vuln=()
  for i in "${!P_PID[@]}"; do
    case "${P_STATUS[$i]}" in
      RESTART_NEEDED) stale+=("PID ${P_PID[$i]} (${P_USER[$i]}): ${P_EXE[$i]} — ${P_CMD[$i]}") ;;
      VULNERABLE|EOL) vuln+=("PID ${P_PID[$i]} (${P_USER[$i]}): Node ${P_VER[$i]} ${P_STATUS[$i]} — ${P_CMD[$i]}") ;;
    esac
  done
  if [ ${#stale[@]} -gt 0 ]; then
    finding high "Running Node.js processes on a replaced binary — restart needed" \
"Node was updated on disk, but these processes still run the old (possibly vulnerable) code. Restart them (pm2 restart / systemctl restart):
$(printf '  %s\n' "${stale[@]}")"
  fi
  if [ ${#vuln[@]} -gt 0 ]; then
    finding high "Running Node.js processes using a vulnerable or end-of-life version" \
"These live processes use an unpatched runtime right now:
$(printf '  %s\n' "${vuln[@]}")"
  fi
  [ "$IS_ROOT" -eq 0 ] && note "Not running as root: other users' Node processes and their CA settings could not be fully checked."
}

# ----------------------------------------------------- eMudhra CA bundles ---

check_ca_bundles() {
  local f line
  if [ -r /etc/environment ]; then
    line=$(sed -n 's/^[[:space:]]*NODE_EXTRA_CA_CERTS=//p' /etc/environment | tr -d '"'"'" | head -n1)
    if [ -n "$line" ] && [ -z "${EXTRA_CA_SEEN[$line]:-}" ]; then EXTRA_CA_SEEN[$line]=1; EXTRA_CA+=("$line"); fi
  fi
  while IFS= read -r line; do
    [ -n "$line" ] && [ -z "${EXTRA_CA_SEEN[$line]:-}" ] && { EXTRA_CA_SEEN[$line]=1; EXTRA_CA+=("$line"); }
  done < <(grep -rhoE 'NODE_EXTRA_CA_CERTS=[^ "'"'"']+' /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null \
            | cut -d= -f2- | sort -u)

  local bad=()
  for f in "${EXTRA_CA[@]}"; do
    if [ ! -r "$f" ]; then
      note "NODE_EXTRA_CA_CERTS points to '$f', which is missing or unreadable."
      continue
    fi
    if have openssl; then
      local n
      n=$(openssl crl2pkcs7 -nocrl -certfile "$f" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -ciE 'emsign|emudhra')
      [ "${n:-0}" -gt 0 ] && bad+=("$f ($n emSign/eMudhra certificate line(s))")
    else
      grep -qiE 'emsign|emudhra' "$f" 2>/dev/null && bad+=("$f")
    fi
  done
  if [ ${#bad[@]} -gt 0 ]; then
    finding medium "Extra CA bundles for Node.js contain eMudhra / emSign certificates" \
"NODE_EXTRA_CA_CERTS adds certificates ON TOP of Node's built-in list, so updating Node does not remove these. Eight eMudhra intermediate keys were compromised (Oct 2026). Remove them unless you have a specific need:
$(printf '  %s\n' "${bad[@]}")"
  fi
  if [ ${#OS_STORE_PROCS[@]} -gt 0 ]; then
    finding info "Node.js processes using the operating system's CA store" \
"These run with --use-openssl-ca / --use-system-ca, so they trust the OS store instead of Node's built-in list. Make sure the OS ca-certificates package is updated for the eMudhra distrust, then restart them:
$(printf '  %s\n' "${OS_STORE_PROCS[@]}")"
  fi
}

# --------------------------------------------------------------- containers ---

CT_NAME=(); CT_IMAGE=(); CT_VER=(); CT_STATUS=()
check_containers() {
  if ! have docker; then
    [ "$DO_CONTAINERS" -eq 1 ] && note "--containers: docker is not installed."
    return
  fi
  local ids
  ids=$(T docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null)
  [ -z "$ids" ] && return
  if [ "$DO_CONTAINERS" -eq 0 ]; then
    note "$(printf '%s\n' "$ids" | wc -l) running Docker container(s) not checked. Re-run with --containers to read the Node version inside each one."
    return
  fi
  local line id name image v
  while IFS='|' read -r id name image; do
    v=$(T docker exec "$id" sh -c 'command -v node >/dev/null 2>&1 && node --version' 2>/dev/null | head -n1 | tr -d 'v\r')
    [ -z "$v" ] && continue
    classify "$v" ""
    CT_NAME+=("$name"); CT_IMAGE+=("$image"); CT_VER+=("$v"); CT_STATUS+=("$C_STATUS")
  done <<< "$ids"
  local i bad=()
  for i in "${!CT_NAME[@]}"; do
    case "${CT_STATUS[$i]}" in VULNERABLE|EOL) bad+=("${CT_NAME[$i]} (${CT_IMAGE[$i]}): Node ${CT_VER[$i]} ${CT_STATUS[$i]}") ;; esac
  done
  if [ ${#bad[@]} -gt 0 ]; then
    finding high "Containers running vulnerable or end-of-life Node.js" \
"Updating the host does not update containers. Rebuild these images on a fixed base (docker build --pull) and redeploy:
$(printf '  %s\n' "${bad[@]}")"
  fi
}

# ---------------------------------------------------------------- run it ---

discover
check_installs
check_processes
check_ca_bundles
check_containers

N_VULN=0; N_ATTN=0
for s in "${R_STATUS[@]}"; do
  case "$s" in
    VULNERABLE|EOL) N_VULN=$((N_VULN+1)) ;;
    UNKNOWN|EOL_BACKPORT) N_ATTN=$((N_ATTN+1)) ;;
  esac
done
N_HIGH=0; N_MED=0
for s in "${F_SEV[@]}"; do
  case "$s" in high) N_HIGH=$((N_HIGH+1)) ;; medium) N_MED=$((N_MED+1)) ;; esac
done

if [ "$N_VULN" -gt 0 ] || [ "$N_HIGH" -gt 0 ]; then
  RESULT=vulnerable; EXIT=1
elif [ "$N_ATTN" -gt 0 ] || [ "$N_MED" -gt 0 ]; then
  RESULT=attention; EXIT=2
elif [ ${#R_PATH[@]} -eq 0 ] && [ ${#CT_NAME[@]} -eq 0 ]; then
  RESULT=no_node_found; EXIT=3
else
  RESULT=ok; EXIT=0
fi

HOST=$(hostname 2>/dev/null || echo unknown)
OS=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || uname -sr)

# ---------------------------------------------------------------- output ---

if [ "$OUT_JSON" -eq 1 ]; then
  printf '{\n'
  printf '  "tool": "node-hostcheck",\n  "version": "%s",\n  "data_date": "%s",\n' "$TOOL_VERSION" "$DATA_DATE"
  printf '  "fixed_releases": ["22.23.4", "24.22.1", "26.12.1"],\n'
  printf '  "host": "%s",\n  "os": "%s",\n  "run_as_root": %s,\n' "$(json_esc "$HOST")" "$(json_esc "$OS")" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
  printf '  "checked_at": "%s",\n  "result": "%s",\n  "exit_code": %d,\n' "$(date -u +%FT%TZ)" "$RESULT" "$EXIT"
  printf '  "installs": ['
  sep=""
  for i in "${!R_PATH[@]}"; do
    printf '%s\n    {"path": "%s", "source": "%s", "version": "%s", "version_from": "%s", "package": "%s", "status": "%s", "note": "%s"}' \
      "$sep" "$(json_esc "${R_PATH[$i]}")" "${R_SRC[$i]}" "$(json_esc "${R_VER[$i]}")" "${R_VSRC[$i]}" \
      "$(json_esc "${R_PKG[$i]}")" "${R_STATUS[$i]}" "$(json_esc "${R_NOTE[$i]}")"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "processes": ['
  sep=""
  for i in "${!P_PID[@]}"; do
    printf '%s\n    {"pid": %s, "user": "%s", "exe": "%s", "version": "%s", "status": "%s", "cmd": "%s"}' \
      "$sep" "${P_PID[$i]}" "$(json_esc "${P_USER[$i]}")" "$(json_esc "${P_EXE[$i]}")" "$(json_esc "${P_VER[$i]}")" \
      "${P_STATUS[$i]}" "$(json_esc "${P_CMD[$i]}")"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "containers": ['
  sep=""
  for i in "${!CT_NAME[@]}"; do
    printf '%s\n    {"name": "%s", "image": "%s", "version": "%s", "status": "%s"}' \
      "$sep" "$(json_esc "${CT_NAME[$i]}")" "$(json_esc "${CT_IMAGE[$i]}")" "$(json_esc "${CT_VER[$i]}")" "${CT_STATUS[$i]}"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "extra_ca_bundles": ['
  sep=""
  for f in "${EXTRA_CA[@]}"; do printf '%s"%s"' "$sep" "$(json_esc "$f")"; sep=", "; done
  printf '],\n  "findings": ['
  sep=""
  for i in "${!F_SEV[@]}"; do
    printf '%s\n    {"severity": "%s", "title": "%s", "detail": "%s"}' "$sep" "${F_SEV[$i]}" "$(json_esc "${F_TITLE[$i]}")" "$(json_esc "${F_DETAIL[$i]}")"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "notes": ['
  sep=""
  for n in "${NOTES[@]}"; do printf '%s"%s"' "$sep" "$(json_esc "$n")"; sep=", "; done
  printf ']\n}\n'
  exit "$EXIT"
fi

status_tag() {
  case "$1" in
    PATCHED|PATCHED_BACKPORT) printf '%s[%s]%s' "$GRN" "$1" "$RST" ;;
    VULNERABLE|EOL|RESTART_NEEDED) printf '%s%s[%s]%s' "$RED" "$BLD" "$1" "$RST" ;;
    *) printf '%s[%s]%s' "$YEL" "$1" "$RST" ;;
  esac
}
sev_tag() {
  case "$1" in
    high) printf '%s%s[HIGH]%s' "$RED" "$BLD" "$RST" ;;
    medium) printf '%s[MEDIUM]%s' "$YEL" "$RST" ;;
    *) printf '%s[INFO]%s' "$DIM" "$RST" ;;
  esac
}

echo "${BLD}node-hostcheck $TOOL_VERSION${RST} — Node.js October 2026 security release (CVE-2026-111497 + 9)"
echo "${DIM}Host: $HOST | $OS | root: $([ "$IS_ROOT" -eq 1 ] && echo yes || echo no) | data: $DATA_DATE | fixed: 22.23.4 / 24.22.1 / 26.12.1${RST}"
echo
echo "${BLD}NODE.JS INSTALLS${RST}"
if [ ${#R_PATH[@]} -eq 0 ]; then
  echo "  No Node.js found in the usual locations."
else
  for i in "${!R_PATH[@]}"; do
    printf '  %s %s  %s  %s%s\n' "$(status_tag "${R_STATUS[$i]}")" "${R_VER[$i]:-?}" "${R_SRC[$i]}" "${R_PATH[$i]}" \
      "$([ -n "${R_PKG[$i]}" ] && printf '  %s(%s)%s' "$DIM" "${R_PKG[$i]}" "$RST")"
    printf '      %s\n' "${R_NOTE[$i]}"
  done
fi

echo
echo "${BLD}RUNNING NODE.JS PROCESSES${RST}"
if [ ${#P_PID[@]} -eq 0 ]; then
  echo "  None running."
else
  for i in "${!P_PID[@]}"; do
    printf '  %s PID %s  %s  %s  %s\n' "$(status_tag "${P_STATUS[$i]}")" "${P_PID[$i]}" "${P_USER[$i]}" "${P_VER[$i]:-?}" "${P_EXE[$i]}"
    printf '      %s%s%s\n' "$DIM" "${P_CMD[$i]}" "$RST"
  done
fi

if [ ${#CT_NAME[@]} -gt 0 ]; then
  echo
  echo "${BLD}CONTAINERS${RST}"
  for i in "${!CT_NAME[@]}"; do
    printf '  %s %s  %s  %s\n' "$(status_tag "${CT_STATUS[$i]}")" "${CT_VER[$i]}" "${CT_NAME[$i]}" "${DIM}${CT_IMAGE[$i]}${RST}"
  done
fi

if [ ${#F_SEV[@]} -gt 0 ]; then
  echo
  echo "${BLD}FINDINGS${RST}"
  for i in "${!F_SEV[@]}"; do
    printf '  %s %s\n' "$(sev_tag "${F_SEV[$i]}")" "${F_TITLE[$i]}"
    printf '%s\n' "${F_DETAIL[$i]}" | sed 's/^/    /'
  done
fi

if [ "$N_VULN" -gt 0 ]; then
  echo
  echo "${BLD}WHAT TO DO${RST}"
  echo "  - Update to 22.23.4 / 24.22.1 / 26.12.1 (or your distro's fixed package)."
  echo "  - nvm/fnm/volta: install the fixed version, switch to it, remove old versions services still point at."
  echo "  - Restart every Node process (pm2 restart all / systemctl restart <app>), then run this again."
  echo "  - Rebuild Docker images and single-executable apps (SEA) — they embed their own Node."
  echo "  - Node 20 and older are end-of-life: move to Node 24 or 26."
fi

if [ ${#NOTES[@]} -gt 0 ]; then
  echo
  echo "${BLD}NOTES${RST}"
  for n in "${NOTES[@]}"; do printf '  - %s\n' "$n"; done
fi

echo
case "$RESULT" in
  vulnerable) echo "${RED}${BLD}RESULT: VULNERABLE${RST} — update Node.js and restart the processes listed above." ;;
  attention)  echo "${YEL}${BLD}RESULT: NEEDS ATTENTION${RST} — review the items above." ;;
  no_node_found) echo "${YEL}${BLD}RESULT: NO NODE.JS FOUND${RST} — check containers (--containers) or custom paths (--search DIR)." ;;
  ok) echo "${GRN}${BLD}RESULT: OK${RST} — every Node.js install and running process found is patched." ;;
esac
echo "${DIM}Indicator check only — a clean result is not proof the host is safe.${RST}"
exit "$EXIT"
