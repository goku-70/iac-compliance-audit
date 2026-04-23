#!/usr/bin/env bash
# install-hooks.sh — Install IaC audit git hooks into the current repository.
# Run from inside ANY repository where you want the pre-commit and pre-push hooks.
#
# Usage:
#   bash /path/to/iac-compliance-audit/ci/install-hooks.sh
#   bash /path/to/iac-compliance-audit/ci/install-hooks.sh --uninstall

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_SRC_DIR="$SCRIPT_DIR/hooks"

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo -e "${RED}ERROR:${NC} Run this script from inside a git repository."
  exit 1
}
HOOK_DEST_DIR="$REPO_ROOT/.git/hooks"

install_hook() {
  local name="$1"
  local src="$HOOK_SRC_DIR/$name"
  local dst="$HOOK_DEST_DIR/$name"

  if [[ ! -f "$src" ]]; then
    echo -e "${YELLOW}SKIP:${NC} $name (source not found at $src)"
    return
  fi

  if [[ -f "$dst" ]] && ! grep -q "iac-audit" "$dst" 2>/dev/null; then
    # Existing non-iac hook — append a call to our hook so both run
    local chain="${dst}.iac-audit"
    echo -e "${YELLOW}CHAIN:${NC} $name already exists — chaining iac-audit hook"
    cp "$src" "$chain"
    chmod +x "$chain"
    printf '\n# iac-audit hook (chained)\nbash "%s/.git/hooks/%s.iac-audit"\n' \
      "$(git rev-parse --show-toplevel)" "$name" >> "$dst"
  else
    cp "$src" "$dst"
    chmod +x "$dst"
    echo -e "${GREEN}INSTALLED:${NC} $name → $dst"
  fi
}

uninstall_hook() {
  local name="$1"
  local dst="$HOOK_DEST_DIR/$name"
  local chain="${dst}.iac-audit"

  if [[ -f "$chain" ]]; then
    rm -f "$chain"
    # Remove the two chained lines from the original hook (if they exist)
    sed -i.bak '/# iac-audit hook (chained)/d' "$dst" 2>/dev/null || true
    sed -i.bak '/\.iac-audit/d'                 "$dst" 2>/dev/null || true
    rm -f "${dst}.bak"
    echo -e "${GREEN}REMOVED:${NC} chained $name hook"
  elif [[ -f "$dst" ]] && grep -q "iac-audit" "$dst" 2>/dev/null; then
    rm -f "$dst"
    echo -e "${GREEN}REMOVED:${NC} $name hook"
  else
    echo -e "${YELLOW}SKIP:${NC} $name (not installed or not an iac-audit hook)"
  fi
}

if [[ "${1:-}" == "--uninstall" ]]; then
  echo -e "${CYAN}Uninstalling IaC audit hooks from $REPO_ROOT${NC}"
  uninstall_hook "pre-commit"
  uninstall_hook "pre-push"
  echo ""
  echo -e "${GREEN}Done. Hooks removed.${NC}"
  exit 0
fi

echo -e "${CYAN}Installing IaC audit hooks into $REPO_ROOT${NC}"
echo ""
install_hook "pre-commit"
install_hook "pre-push"
echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "What happens next:"
echo "  git commit  → fast grep scan (no API key needed, ~100ms)"
echo "               blocks on: hardcoded secrets, open SSH to 0.0.0.0/0, privileged containers"
echo "  git push    → full Claude compliance audit (requires ANTHROPIC_API_KEY, ~30-90s)"
echo ""
echo "To set your API key permanently:"
echo "  echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.zshrc && source ~/.zshrc"
echo ""
echo "To configure pre-push severity threshold (default: HIGH):"
echo "  echo 'export IAC_AUDIT_FAIL_ON=CRITICAL' >> ~/.zshrc"
echo ""
echo "To uninstall:"
echo "  bash $0 --uninstall"
