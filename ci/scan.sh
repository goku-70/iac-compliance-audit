#!/usr/bin/env bash
# ci/scan.sh — CI/CD wrapper for the IaC Compliance Audit Claude Code skill
#
# Usage:
#   bash ci/scan.sh [options]
#
# Options:
#   --path        <dir>    Directory to scan            (default: .)
#   --mode        <mode>   static|live|all              (default: static)
#   --framework   <fw>     PCI-DSS|SOC2|GDPR|HIPAA|ALL (default: ALL)
#   --severity    <sev>    CRITICAL|HIGH|ALL            (default: ALL)
#   --output      <fmt>    text|html|json               (default: html)
#   --fail-on     <sev>    CRITICAL|HIGH|MEDIUM|ALL|NONE (default: CRITICAL)
#   --report-dir  <dir>    Where to save reports        (default: ./iac-audit-reports)
#   --domain      <d>      01-20 or ALL                 (default: ALL)
#   --cloud       <cld>    AWS|GCP|Azure|ALL            (default: ALL)
#
# Required env:
#   ANTHROPIC_API_KEY   — Anthropic API key (pass via CI secret, never hardcode)
#
# Optional env (same names as flags, take lower priority than CLI flags):
#   IAC_AUDIT_PATH, IAC_AUDIT_MODE, IAC_AUDIT_FRAMEWORK, IAC_AUDIT_SEVERITY,
#   IAC_AUDIT_OUTPUT, IAC_AUDIT_FAIL_ON, IAC_AUDIT_REPORT_DIR,
#   IAC_AUDIT_DOMAIN, IAC_AUDIT_CLOUD

set -euo pipefail

# ─── Helpers ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[iac-audit]${NC} $*"; }
warn() { echo -e "${YELLOW}[iac-audit] WARN:${NC} $*" >&2; }
err()  { echo -e "${RED}[iac-audit] ERROR:${NC} $*" >&2; }
ok()   { echo -e "${GREEN}[iac-audit] OK:${NC} $*"; }

# ─── Defaults from environment ────────────────────────────────────────────────

SCAN_PATH="${IAC_AUDIT_PATH:-.}"
MODE="${IAC_AUDIT_MODE:-static}"
FRAMEWORK="${IAC_AUDIT_FRAMEWORK:-ALL}"
SEVERITY="${IAC_AUDIT_SEVERITY:-ALL}"
OUTPUT_FMT="${IAC_AUDIT_OUTPUT:-html}"
FAIL_ON="${IAC_AUDIT_FAIL_ON:-CRITICAL}"
REPORT_DIR="${IAC_AUDIT_REPORT_DIR:-./iac-audit-reports}"
DOMAIN="${IAC_AUDIT_DOMAIN:-ALL}"
CLOUD="${IAC_AUDIT_CLOUD:-ALL}"

# ─── Parse CLI flags (override env) ───────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case $1 in
    --path)       SCAN_PATH="$2";  shift 2 ;;
    --mode)       MODE="$2";       shift 2 ;;
    --framework)  FRAMEWORK="$2";  shift 2 ;;
    --severity)   SEVERITY="$2";   shift 2 ;;
    --output)     OUTPUT_FMT="$2"; shift 2 ;;
    --fail-on)    FAIL_ON="$2";    shift 2 ;;
    --report-dir) REPORT_DIR="$2"; shift 2 ;;
    --domain)     DOMAIN="$2";     shift 2 ;;
    --cloud)      CLOUD="$2";      shift 2 ;;
    --help|-h)
      sed -n '3,17p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) err "Unknown flag: $1  (run with --help for usage)"; exit 1 ;;
  esac
done

# ─── Input validation ─────────────────────────────────────────────────────────

validate_enum() {
  local val="$1" name="$2"; shift 2
  local allowed=("$@")
  for a in "${allowed[@]}"; do
    [[ "$val" == "$a" ]] && return 0
  done
  err "Invalid value for $name: '$val'. Allowed: ${allowed[*]}"
  exit 1
}

validate_enum "$MODE"      "--mode"      static live all
validate_enum "$OUTPUT_FMT" "--output"   text html json
validate_enum "$FAIL_ON"   "--fail-on"   CRITICAL HIGH MEDIUM ALL NONE
validate_enum "$SEVERITY"  "--severity"  CRITICAL HIGH ALL
validate_enum "$CLOUD"     "--cloud"     AWS GCP Azure ALL

# Framework and domain allow compound values (e.g. "PCI-DSS,SOC2" or "01,04,09")
# so we only check for obviously unsafe characters rather than exact matches
if [[ "$FRAMEWORK" =~ [^A-Z0-9,_-] ]]; then
  err "Invalid --framework value: '$FRAMEWORK'"; exit 1
fi
if [[ "$DOMAIN" =~ [^A-Z0-9,_-] ]]; then
  err "Invalid --domain value: '$DOMAIN'"; exit 1
fi

# ─── Path validation ──────────────────────────────────────────────────────────

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  err "ANTHROPIC_API_KEY is not set. Export it from your CI secrets."
  exit 1
fi

# Resolve to an absolute canonical path — this defuses all ../.. traversal attempts
RESOLVED=$(realpath "$SCAN_PATH" 2>/dev/null) || {
  err "Path does not exist or cannot be resolved: $SCAN_PATH"
  exit 1
}

# Reject if the original input tried to traverse (catches attempts like ../../etc)
# We test the *original* value before realpath normalised it
if [[ "$SCAN_PATH" == *".."* ]]; then
  err "Path traversal detected in --path ('$SCAN_PATH'). Refusing to scan."
  exit 1
fi

if ! command -v claude &>/dev/null; then
  err "claude CLI not found. Install: npm install -g @anthropic-ai/claude-code"
  exit 1
fi

# ─── Setup ────────────────────────────────────────────────────────────────────

mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EXT="md"
[[ "$OUTPUT_FMT" == "html" ]] && EXT="html"
[[ "$OUTPUT_FMT" == "json" ]] && EXT="json"
REPORT_FILE="$REPORT_DIR/iac-audit-${TIMESTAMP}.${EXT}"
LATEST_LINK="$REPORT_DIR/latest.${EXT}"

# Install skill — always sync from repo source when available
SKILL_DIR="$HOME/.claude/skills/iac-audit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="$SCRIPT_DIR/../skills/iac-audit/SKILL.md"

if [[ -f "$SKILL_SRC" ]]; then
  mkdir -p "$SKILL_DIR"
  cp "$SKILL_SRC" "$SKILL_DIR/SKILL.md"
  log "Skill installed: $SKILL_DIR/SKILL.md"
elif [[ ! -f "$SKILL_DIR/SKILL.md" ]]; then
  err "Cannot find SKILL.md at '$SKILL_SRC' or '$SKILL_DIR/SKILL.md'"
  err "Clone the iac-compliance-audit repo and run from there, or install the skill manually."
  exit 1
fi

# ─── Run audit ────────────────────────────────────────────────────────────────

PROMPT="/iac-audit --mode $MODE --framework $FRAMEWORK --path $RESOLVED --severity $SEVERITY --output $OUTPUT_FMT --fail-on $FAIL_ON --domain $DOMAIN --cloud $CLOUD"

log "Starting IaC Compliance Audit…"
log "  Scan path : $RESOLVED"
log "  Mode      : $MODE"
log "  Frameworks: $FRAMEWORK"
log "  Output    : $OUTPUT_FMT → $REPORT_FILE"
log "  Fail-on   : $FAIL_ON"

# 10-minute hard timeout prevents CI from hanging on API unresponsiveness
CLAUDE_TIMEOUT="${IAC_AUDIT_TIMEOUT:-600}"

{
  timeout "$CLAUDE_TIMEOUT" claude --print "$PROMPT" 2>&1
} > "$REPORT_FILE" || {
  STATUS=$?
  if [[ "$STATUS" -eq 124 ]]; then
    err "claude timed out after ${CLAUDE_TIMEOUT}s. Check API status or increase IAC_AUDIT_TIMEOUT."
  else
    err "claude exited with status $STATUS. Partial output may be in $REPORT_FILE."
  fi
  # Fall through — partial output may still contain the CI summary line
}

# ─── Parse CI summary line ────────────────────────────────────────────────────

CI_LINE=$(grep -o 'IAC_AUDIT_CI: {[^}]*}' "$REPORT_FILE" 2>/dev/null | tail -1 || true)

if [[ -n "$CI_LINE" ]]; then
  JSON="${CI_LINE#IAC_AUDIT_CI: }"
  _num() { echo "$1" | grep -o "\"$2\":[0-9]*" | grep -o '[0-9]*' || echo 0; }
  CRITICAL_N=$(_num "$JSON" critical)
  HIGH_N=$(_num     "$JSON" high)
  MEDIUM_N=$(_num   "$JSON" medium)
  LOW_N=$(_num      "$JSON" low)
  EXIT_CODE=$(_num  "$JSON" exit_code)
  PCI_SCORE=$(echo  "$JSON" | grep -o '"pci":[0-9]*'  | grep -o '[0-9]*' || echo "?")
  SOC2_SCORE=$(echo "$JSON" | grep -o '"soc2":[0-9]*' | grep -o '[0-9]*' || echo "?")
  GDPR_SCORE=$(echo "$JSON" | grep -o '"gdpr":[0-9]*' | grep -o '[0-9]*' || echo "?")
  HIPAA_SCORE=$(echo "$JSON"| grep -o '"hipaa":[0-9]*'| grep -o '[0-9]*' || echo "?")
else
  warn "CI summary line not found in report — falling back to keyword scan."
  CRITICAL_N=$(grep -c '\bCRITICAL\b' "$REPORT_FILE" 2>/dev/null || echo 0)
  HIGH_N=$(grep     -c '\bHIGH\b'     "$REPORT_FILE" 2>/dev/null || echo 0)
  MEDIUM_N=$(grep   -c '\bMEDIUM\b'   "$REPORT_FILE" 2>/dev/null || echo 0)
  LOW_N=$(grep      -c '\bLOW\b'      "$REPORT_FILE" 2>/dev/null || echo 0)
  PCI_SCORE="?"; SOC2_SCORE="?"; GDPR_SCORE="?"; HIPAA_SCORE="?"; EXIT_CODE=0

  case "$FAIL_ON" in
    CRITICAL) [[ "$CRITICAL_N" -gt 0 ]] && EXIT_CODE=1 ;;
    HIGH)     [[ "$CRITICAL_N" -gt 0 || "$HIGH_N" -gt 0 ]] && EXIT_CODE=1 ;;
    MEDIUM)   [[ "$CRITICAL_N" -gt 0 || "$HIGH_N" -gt 0 || "$MEDIUM_N" -gt 0 ]] && EXIT_CODE=1 ;;
    ALL)      [[ "$((CRITICAL_N + HIGH_N + MEDIUM_N + LOW_N))" -gt 0 ]] && EXIT_CODE=1 ;;
    NONE)     EXIT_CODE=0 ;;
  esac
fi

# ─── Symlink "latest" report ──────────────────────────────────────────────────

ln -sf "$(basename "$REPORT_FILE")" "$LATEST_LINK" 2>/dev/null || true

# ─── GitHub Actions outputs ───────────────────────────────────────────────────

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  {
    echo "## IaC Compliance Audit Results"
    echo ""
    echo "| Severity | Count |"
    echo "|---|---|"
    echo "| 🔴 CRITICAL | **${CRITICAL_N}** |"
    echo "| 🟠 HIGH     | **${HIGH_N}** |"
    echo "| 🟡 MEDIUM   | ${MEDIUM_N} |"
    echo "| 🔵 LOW      | ${LOW_N} |"
    echo ""
    echo "**Scores:** PCI DSS ${PCI_SCORE}/100 · SOC 2 ${SOC2_SCORE}/100 · GDPR ${GDPR_SCORE}/100 · HIPAA ${HIPAA_SCORE}/100"
    echo ""
    echo "Report: \`${REPORT_FILE}\`"
    if [[ "$EXIT_CODE" -eq 1 ]]; then
      echo ""
      echo "> ❌ Build failed: findings at or above **${FAIL_ON}** severity detected."
    else
      echo ""
      echo "> ✅ No findings at or above **${FAIL_ON}** severity."
    fi
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}" 2>/dev/null || true

  {
    echo "critical=${CRITICAL_N}"
    echo "high=${HIGH_N}"
    echo "medium=${MEDIUM_N}"
    echo "low=${LOW_N}"
    echo "report-file=${REPORT_FILE}"
    echo "exit-code=${EXIT_CODE}"
  } >> "${GITHUB_OUTPUT:-/dev/null}" 2>/dev/null || true
fi

# ─── Print summary ────────────────────────────────────────────────────────────

echo ""
echo "┌──────────────────────────────────────────────────────────┐"
echo "│              IaC Compliance Audit Summary                │"
echo "├──────────────────────────────────────────────────────────┤"
printf "│  %-20s %-35s │\n" "Scan path:"   "$RESOLVED"
printf "│  %-20s %-35s │\n" "Mode:"        "$MODE"
printf "│  %-20s %-35s │\n" "Frameworks:"  "$FRAMEWORK"
echo "├──────────────────────────────────────────────────────────┤"
printf "│  🔴 %-17s %-35s │\n" "CRITICAL:" "$CRITICAL_N findings"
printf "│  🟠 %-17s %-35s │\n" "HIGH:"     "$HIGH_N findings"
printf "│  🟡 %-17s %-35s │\n" "MEDIUM:"   "$MEDIUM_N findings"
printf "│  🔵 %-17s %-35s │\n" "LOW:"      "$LOW_N findings"
echo "├──────────────────────────────────────────────────────────┤"
printf "│  %-20s %-35s │\n" "PCI DSS:"     "${PCI_SCORE}/100"
printf "│  %-20s %-35s │\n" "SOC 2:"       "${SOC2_SCORE}/100"
printf "│  %-20s %-35s │\n" "GDPR:"        "${GDPR_SCORE}/100"
printf "│  %-20s %-35s │\n" "HIPAA:"       "${HIPAA_SCORE}/100"
echo "├──────────────────────────────────────────────────────────┤"
printf "│  %-20s %-35s │\n" "Report:" "$REPORT_FILE"
echo "└──────────────────────────────────────────────────────────┘"
echo ""

if [[ "$EXIT_CODE" -eq 1 ]]; then
  err "Audit FAILED — findings at or above --fail-on=${FAIL_ON} detected."
  err "Open the report: open ${REPORT_FILE}"
else
  ok "Audit passed for --fail-on=${FAIL_ON} threshold."
fi

exit "$EXIT_CODE"
