#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly SYSTEM_PACKAGES=(
  python3
  python3-venv
  python3-pip
  nmap
  subfinder
  httpx-toolkit
  whatweb
)

DRY_RUN=false
VERIFY_ONLY=false

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap-kali.sh [--dry-run | --verify-only]

Install Hacker AI and its approved external tools on Kali Linux 2026/rolling.
  --dry-run      Print installation commands without changing the system.
  --verify-only  Perform local checks only; do not install or access the network.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  if [[ "$DRY_RUN" == false ]]; then
    "$@"
  fi
}

for argument in "$@"; do
  case "$argument" in
    --dry-run) DRY_RUN=true ;;
    --verify-only) VERIFY_ONLY=true ;;
    -h | --help) usage; exit 0 ;;
    *) die "Unknown argument: $argument" ;;
  esac
done

if [[ "$DRY_RUN" == true && "$VERIFY_ONLY" == true ]]; then
  die '--dry-run and --verify-only cannot be combined'
fi

if [[ "$DRY_RUN" == false ]]; then
  [[ -r /etc/os-release ]] || die 'Cannot identify this operating system'
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == kali ]] || die 'This bootstrap script supports Kali Linux only'
  case "$(uname -m)" in
    x86_64 | aarch64 | arm64) ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
  [[ "${EUID}" -ne 0 ]] || die 'Run as a regular user; the script uses sudo only for APT'
fi

cd "$PROJECT_ROOT"

if [[ "$VERIFY_ONLY" == false ]]; then
  run sudo apt-get update
  run sudo apt-get install --no-install-recommends -y "${SYSTEM_PACKAGES[@]}"

  if command -v uv >/dev/null 2>&1; then
    run uv sync --locked --extra dev
  else
    run python3 -m venv .venv
    run .venv/bin/python -m pip install -e '.[dev]'
  fi
fi

if [[ "$DRY_RUN" == true ]]; then
  printf '%s\n' '+ .venv/bin/hacker-ai tools doctor'
  printf '%s\n' '+ .venv/bin/hacker-ai doctor'
  exit 0
fi

[[ -x .venv/bin/hacker-ai ]] || die 'Project virtual environment is missing; run without --verify-only first'
run .venv/bin/hacker-ai tools doctor
run .venv/bin/hacker-ai doctor

cat <<'EOF'

Bootstrap complete. Network/tool execution remains OFF by default.
Activate with: source .venv/bin/activate
Only for an explicitly authorized scoped run:
  export HACKER_AI_ALLOW_NETWORK_EXECUTION=true
EOF