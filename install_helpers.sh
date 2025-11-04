#!/usr/bin/env bash
# AWShawk helper installer (latest+fallback)
# Tools: trufflehog, gitleaks, jq
# Arch:  x86_64/amd64, arm64/aarch64
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR="${ROOT_DIR}/helper"
mkdir -p "${HELPER_DIR}"
cd "${HELPER_DIR}"

echo "[*] AWShawk helper installer"
echo "[*] Target: ${HELPER_DIR}"

OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux) : ;;
  *) echo "[!] Unsupported OS: $OS (Linux required)"; exit 1;;
esac
case "$ARCH" in
  x86_64|amd64)   ARCH_FAMILY="amd64" ;;
  aarch64|arm64)  ARCH_FAMILY="arm64" ;;
  *) echo "[!] Unsupported ARCH: $ARCH"; exit 1;;
esac
echo "[*] Detected: ${OS} ${ARCH} (${ARCH_FAMILY})"

# --- helpers ---
download() { curl -L --fail --retry 3 -o "$2" "$1"; }
log_version() { local name="$1"; shift; { printf "%s: " "$name"; if "$@" >/tmp/.ver$$ 2>&1; then head -n1 /tmp/.ver$$; else echo "<unknown>"; fi; } >> "${HELPER_DIR}/versions.log"; rm -f /tmp/.ver$$ || true; }
add_wrapper() { printf "%s\n" "$2" > "${HELPER_DIR}/$1"; chmod +x "${HELPER_DIR}/$1"; }

: > "${HELPER_DIR}/versions.log"
: > "${HELPER_DIR}/CHECKSUMS.txt"

# =========================================================
# 1) TruffleHog  — preferred: official install script
# =========================================================
if [ ! -x "${HELPER_DIR}/trufflehog" ]; then
  echo "[*] Installing trufflehog (official installer)…"
  set +e
  # Official install script installs the correct asset and sets mode. (recommended)  【ref: trufflesecurity docs】
  curl -sSfL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" \
    | sh -s -- -b "${HELPER_DIR}" >/tmp/.trh_installer.log 2>&1
  RC=$?
  set -e

  if [ $RC -ne 0 ] || [ ! -x "${HELPER_DIR}/trufflehog" ]; then
    echo "[!] Installer failed, falling back to Release asset discovery…"
    # Fallback: query GitHub API for latest asset matching our arch and extract
    API_URL="https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
    TMP_JSON="$(mktemp -t trh_release.XXXXXX.json)"
    curl -sSfL "$API_URL" -o "$TMP_JSON"
    if [ "${ARCH_FAMILY}" = "amd64" ]; then
      ASSET_URL="$(grep -Eo '"browser_download_url":\s*"[^"]*linux_amd64[^"]*\.tar\.gz"' "$TMP_JSON" | head -n1 | cut -d'"' -f4)"
    else
      ASSET_URL="$(grep -Eo '"browser_download_url":\s*"[^"]*linux_arm64[^"]*\.tar\.gz"' "$TMP_JSON" | head -n1 | cut -d'"' -f4)"
    fi
    rm -f "$TMP_JSON"
    [ -n "${ASSET_URL:-}" ] || { echo "[!] Could not resolve trufflehog asset URL"; exit 2; }
    TMP_TAR="$(mktemp -t trufflehog.XXXXXX.tar.gz)"
    download "$ASSET_URL" "$TMP_TAR"
    tar -xzf "$TMP_TAR" -C "${HELPER_DIR}" 2>/dev/null || true
    rm -f "$TMP_TAR"
    # Normalize location
    if [ ! -x "${HELPER_DIR}/trufflehog" ]; then
      CAND="$(find "${HELPER_DIR}" -maxdepth 2 -type f -name 'trufflehog' -print -quit)"
      [ -n "$CAND" ] && mv "$CAND" "${HELPER_DIR}/trufflehog"
    fi
    [ -x "${HELPER_DIR}/trufflehog" ] || { echo "[!] trufflehog binary not found after extraction"; exit 2; }
    chmod +x "${HELPER_DIR}/trufflehog"
  fi
else
  echo "[=] trufflehog already present, skipping."
fi
sha256sum "${HELPER_DIR}/trufflehog" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
log_version "trufflehog" "${HELPER_DIR}/trufflehog" --version || true

# =========================================================
# 2) Gitleaks — latest/download with API fallback
# =========================================================
if [ ! -x "${HELPER_DIR}/gitleaks" ]; then
  echo "[*] Installing gitleaks…"
  if [ "${ARCH_FAMILY}" = "amd64" ]; then
    GL_LATEST="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz"
    PATTERN='linux_x64.*\.tar\.gz'
  else
    GL_LATEST="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_arm64.tar.gz"
    PATTERN='linux_arm64.*\.tar\.gz'
  fi
  TMP_TAR="$(mktemp -t gitleaks.XXXXXX.tar.gz)"
  set +e
  curl -L --fail --retry 2 -o "$TMP_TAR" "$GL_LATEST"
  RC=$?
  set -e
  if [ $RC -ne 0 ]; then
    echo "[!] Latest shortcut failed, resolving via GitHub API…"
    API_URL="https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
    TMP_JSON="$(mktemp -t gl_release.XXXXXX.json)"
    curl -sSfL "$API_URL" -o "$TMP_JSON"
    ASSET_URL="$(grep -Eo "\"browser_download_url\":\s*\"[^\"]*${PATTERN}\"" "$TMP_JSON" | head -n1 | cut -d'"' -f4)"
    rm -f "$TMP_JSON"
    [ -n "${ASSET_URL:-}" ] || { echo "[!] Could not resolve gitleaks asset URL"; exit 2; }
    download "$ASSET_URL" "$TMP_TAR"
  fi
  tar -xzf "$TMP_TAR" -C "${HELPER_DIR}" 2>/dev/null || true
  rm -f "$TMP_TAR"
  # Some releases unpack into a folder; normalize
  if [ ! -x "${HELPER_DIR}/gitleaks" ]; then
    CAND="$(find "${HELPER_DIR}" -maxdepth 2 -type f -name 'gitleaks' -print -quit)"
    [ -n "$CAND" ] && mv "$CAND" "${HELPER_DIR}/gitleaks"
  fi
  [ -x "${HELPER_DIR}/gitleaks" ] || { echo "[!] gitleaks binary not found after extraction"; exit 2; }
  chmod +x "${HELPER_DIR}/gitleaks"
else
  echo "[=] gitleaks already present, skipping."
fi
sha256sum "${HELPER_DIR}/gitleaks" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
log_version "gitleaks" "${HELPER_DIR}/gitleaks" version || true

# =========================================================
# 3) jq — latest/download with version fallback
# =========================================================
if [ ! -x "${HELPER_DIR}/jq" ]; then
  echo "[*] Installing jq…"
  if [ "${ARCH_FAMILY}" = "amd64" ]; then
    JQ_LATEST="https://github.com/jqlang/jq/releases/latest/download/jq-linux-amd64"
    JQ_FALLBK="https://github.com/jqlang/jq/releases/download/jq-1.8.0/jq-linux-amd64"
  else
    JQ_LATEST="https://github.com/jqlang/jq/releases/latest/download/jq-linux-aarch64"
    JQ_FALLBK="https://github.com/jqlang/jq/releases/download/jq-1.8.0/jq-linux-aarch64"
  fi
  set +e
  curl -L --fail --retry 2 -o "${HELPER_DIR}/jq" "$JQ_LATEST"
  RC=$?
  set -e
  if [ $RC -ne 0 ]; then
    echo "[!] Latest jq failed, using fallback version…"
    download "$JQ_FALLBK" "${HELPER_DIR}/jq"
  fi
  chmod +x "${HELPER_DIR}/jq"
else
  echo "[=] jq already present, skipping."
fi
sha256sum "${HELPER_DIR}/jq" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
log_version "jq" "${HELPER_DIR}/jq" --version || true

# =========================================================
# Wrapper scripts (prefer bundled, else PATH)
# =========================================================
add_wrapper "run_trufflehog.sh" '#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "${HERE}/trufflehog" ]; then exec "${HERE}/trufflehog" "$@"; fi
if command -v trufflehog >/dev/null 2>&1; then exec trufflehog "$@"; fi
echo "[!] trufflehog not found (helper or system)"; exit 2
'
add_wrapper "run_gitleaks.sh" '#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "${HERE}/gitleaks" ]; then exec "${HERE}/gitleaks" "$@"; fi
if command -v gitleaks >/dev/null 2>&1; then exec gitleaks "$@"; fi
echo "[!] gitleaks not found (helper or system)"; exit 2
'
add_wrapper "check_helpers.sh" '#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "Helpers in: $HERE"
for bin in trufflehog gitleaks jq; do
  if [ -x "${HERE}/${bin}" ]; then
    printf " - %-10s: bundled (%s)\n" "$bin" "${HERE}/${bin}"
  elif command -v "${bin}" >/dev/null 2>&1; then
    printf " - %-10s: system   (%s)\n" "$bin" "$(command -v ${bin})"
  else
    printf " - %-10s: MISSING\n" "$bin"
  fi
done
'

echo
echo "[*] Installed:"
[ -x "${HELPER_DIR}/trufflehog" ] && echo " - trufflehog" || echo " - trufflehog: missing"
[ -x "${HELPER_DIR}/gitleaks" ]   && echo " - gitleaks"   || echo " - gitleaks: missing"
[ -x "${HELPER_DIR}/jq" ]         && echo " - jq"         || echo " - jq: missing"
echo
echo "[*] Wrapper scripts:"
echo " - run_trufflehog.sh"
echo " - run_gitleaks.sh"
echo " - check_helpers.sh"
echo
echo "[*] Logs:"
echo " - versions.log"
echo " - CHECKSUMS.txt"
echo
echo "[*] Done."
