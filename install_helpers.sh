#!/usr/bin/env bash
#
# install_helpers.sh
# Installs helper binaries for AWShawk into ./helper/
# - Downloads "latest" releases with stable fallbacks
# - Supports Linux x86_64 and arm64
# - Creates wrapper scripts and logs versions + checksums
#
# Tools: trufflehog, gitleaks, jq
# NOTE: We intentionally DO NOT bundle AWS CLI to avoid false positives in HAS_AWSCLI.
#       If you need AWS CLI, install it system-wide or add it yourself later.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_DIR="${ROOT_DIR}/helper"
mkdir -p "${HELPER_DIR}"
cd "${HELPER_DIR}"

echo "[*] AWShawk helper installer"
echo "[*] Target: ${HELPER_DIR}"

# ---------------------------
# Detect OS/ARCH
# ---------------------------
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux) ;;
  *) echo "[!] Unsupported OS: $OS (this installer targets Linux)"; exit 1;;
esac

case "$ARCH" in
  x86_64|amd64)   ARCH_FAMILY="amd64";;
  aarch64|arm64)  ARCH_FAMILY="arm64";;
  *) echo "[!] Unsupported ARCH: $ARCH"; exit 1;;
esac

echo "[*] Detected: ${OS} ${ARCH} (${ARCH_FAMILY})"

# ---------------------------
# Helpers
# ---------------------------
download_file() {
  # download_file <url> <out>
  local url="$1" out="$2"
  echo "[*] Downloading: $url"
  curl -L --fail --retry 3 -o "$out" "$url"
}

download_with_fallback() {
  # download_with_fallback <primary_url> <fallback_url> <out> <chmod+x?>
  local primary="$1" fallback="$2" out="$3" make_exec="${4:-true}"
  if curl -L --fail --retry 2 -o "$out" "$primary" ; then
    :
  else
    echo "[!] Primary failed, trying fallback: $fallback"
    curl -L --fail --retry 3 -o "$out" "$fallback"
  fi
  if [ "${make_exec}" = "true" ]; then chmod +x "$out" || true; fi
}

log_version() {
  # log_version <name> <cmd>  (writes versions.log)
  local name="$1"; shift
  {
    printf "%s: " "$name"
    if "$@" >/tmp/.ver$$ 2>&1; then
      head -n 1 /tmp/.ver$$
    else
      echo "<unable to determine>"
    fi
  } >> "${HELPER_DIR}/versions.log"
  rm -f /tmp/.ver$$ || true
}

add_wrapper() {
  # add_wrapper <filename> <content>
  local fname="$1" ; shift
  local content="$*"
  printf "%s\n" "${content}" > "${HELPER_DIR}/${fname}"
  chmod +x "${HELPER_DIR}/${fname}"
}

# Clean logs
: > "${HELPER_DIR}/versions.log"
: > "${HELPER_DIR}/CHECKSUMS.txt"

# ---------------------------
# URLs (latest + fallback)
# ---------------------------
if [ "${ARCH_FAMILY}" = "amd64" ]; then
  TRUFFLEHOG_LATEST="https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64"
  TRUFFLEHOG_FALLBK="https://github.com/trufflesecurity/trufflehog/releases/download/v3.74.1/trufflehog_linux_amd64"

  GITLEAKS_LATEST="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz"
  GITLEAKS_FALLBK="https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz"

  JQ_LATEST="https://github.com/jqlang/jq/releases/latest/download/jq-linux-amd64"
  JQ_FALLBK="https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64"

elif [ "${ARCH_FAMILY}" = "arm64" ]; then
  TRUFFLEHOG_LATEST="https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_arm64"
  TRUFFLEHOG_FALLBK="https://github.com/trufflesecurity/trufflehog/releases/download/v3.74.1/trufflehog_linux_arm64"

  # gitleaks arm64 artifact name follows this pattern in current releases:
  GITLEAKS_LATEST="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_arm64.tar.gz"
  GITLEAKS_FALLBK="https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_arm64.tar.gz"

  # jq arm64 (aarch64)
  JQ_LATEST="https://github.com/jqlang/jq/releases/latest/download/jq-linux-aarch64"
  JQ_FALLBK="https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-aarch64"
fi

# ---------------------------
# Install: trufflehog
# ---------------------------
if [ ! -x "${HELPER_DIR}/trufflehog" ]; then
  echo "[*] Installing trufflehog..."
  download_with_fallback "${TRUFFLEHOG_LATEST}" "${TRUFFLEHOG_FALLBK}" "${HELPER_DIR}/trufflehog" true
else
  echo "[=] trufflehog already present, skipping."
fi
sha256sum "${HELPER_DIR}/trufflehog" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
log_version "trufflehog" "${HELPER_DIR}/trufflehog" --version || true

# ---------------------------
# Install: gitleaks (tar.gz)
# ---------------------------
if [ ! -x "${HELPER_DIR}/gitleaks" ]; then
  echo "[*] Installing gitleaks..."
  TMP_TAR="$(mktemp -t gitleaks.XXXXXX.tar.gz)"
  if curl -L --fail --retry 2 -o "$TMP_TAR" "${GITLEAKS_LATEST}" ; then
    :
  else
    echo "[!] Latest failed, trying fallback…"
    curl -L --fail --retry 3 -o "$TMP_TAR" "${GITLEAKS_FALLBK}"
  fi
  tar -xzf "$TMP_TAR" -C "${HELPER_DIR}" 2>/dev/null || true
  # Some releases untar to a folder, others drop the binary directly. Normalize.
  if [ ! -x "${HELPER_DIR}/gitleaks" ]; then
    # Try to find the binary
    BIN="$(tar -tzf "$TMP_TAR" | grep -E '/?gitleaks$' | head -n1 || true)"
    if [ -n "$BIN" ] && [ -f "${HELPER_DIR}/${BIN}" ]; then
      mv "${HELPER_DIR}/${BIN}" "${HELPER_DIR}/gitleaks" || true
    fi
  fi
  rm -f "$TMP_TAR"
  chmod +x "${HELPER_DIR}/gitleaks" || true
else
  echo "[=] gitleaks already present, skipping."
fi
[ -f "${HELPER_DIR}/gitleaks" ] && sha256sum "${HELPER_DIR}/gitleaks" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
[ -f "${HELPER_DIR}/gitleaks" ] && log_version "gitleaks" "${HELPER_DIR}/gitleaks" version || true

# ---------------------------
# Install: jq
# ---------------------------
if [ ! -x "${HELPER_DIR}/jq" ]; then
  echo "[*] Installing jq..."
  download_with_fallback "${JQ_LATEST}" "${JQ_FALLBK}" "${HELPER_DIR}/jq" true
else
  echo "[=] jq already present, skipping."
fi
sha256sum "${HELPER_DIR}/jq" >> "${HELPER_DIR}/CHECKSUMS.txt" 2>/dev/null || true
log_version "jq" "${HELPER_DIR}/jq" --version || true

# ---------------------------
# Create wrapper scripts
# ---------------------------
add_wrapper "run_trufflehog.sh" '#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "${HERE}/trufflehog" ]; then
  exec "${HERE}/trufflehog" "$@"
fi
if command -v trufflehog >/dev/null 2>&1; then
  exec trufflehog "$@"
fi
echo "[!] trufflehog not found (helper or system)."
exit 2
'

add_wrapper "run_gitleaks.sh" '#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "${HERE}/gitleaks" ]; then
  exec "${HERE}/gitleaks" "$@"
fi
if command -v gitleaks >/dev/null 2>&1; then
  exec gitleaks "$@"
fi
echo "[!] gitleaks not found (helper or system)."
exit 2
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

# ---------------------------
# Summary
# ---------------------------
echo
echo "[*] Installed helper binaries:"
[ -x "${HELPER_DIR}/trufflehog" ] && echo " - trufflehog" || echo " - trufflehog: missing"
[ -x "${HELPER_DIR}/gitleaks" ]   && echo " - gitleaks"   || echo " - gitleaks: missing"
[ -x "${HELPER_DIR}/jq" ]         && echo " - jq"         || echo " - jq: missing"
echo
echo "[*] Wrapper scripts created:"
echo " - run_trufflehog.sh"
echo " - run_gitleaks.sh"
echo " - check_helpers.sh"
echo
echo "[*] Logs:"
echo " - versions.log"
echo " - CHECKSUMS.txt"
echo
echo "[*] Done. You can now run:"
echo "   ${HELPER_DIR}/check_helpers.sh"
