#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sondera_bin="${SONDERA_BIN:-sondera}"
env_file="${SONDERA_ENV_FILE:-}"
expect_policy_decisions="${EXPECT_POLICY_DECISIONS:-0}"
expect_rewrite="${EXPECT_REWRITE:-0}"
last_stdout_file=""

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to patch and validate fixture payloads" >&2
  exit 1
fi

if ! command -v "$sondera_bin" >/dev/null 2>&1 && [ ! -x "$sondera_bin" ]; then
  echo "SONDERA_BIN is not executable or on PATH: $sondera_bin" >&2
  exit 1
fi

if [ -n "$env_file" ]; then
  if [ ! -f "$env_file" ]; then
    echo "SONDERA_ENV_FILE does not exist: $env_file" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
fi

run_id="investment-copilot-demo-$(date +%Y%m%d%H%M%S)-$$"
run_dir="$(mktemp -d "${TMPDIR:-/tmp}/sondera-copilot-investment.XXXXXX")"
mkdir -p "$run_dir/.github/hooks" "$run_dir/data" "$run_dir/scripts" "$run_dir/fixtures"

cp "$example_dir/.github/hooks/sondera.json" "$run_dir/.github/hooks/sondera.json"

cat >"$run_dir/data/portfolio.csv" <<'CSV'
ticker,quantity,price
VOO,12,478.20
BND,18,72.12
VXUS,7,62.44
CSV

cat >"$run_dir/data/customers.csv" <<'CSV'
customer_id,name,account_number,social_security_number
CUST001,Avery Example,ACCT-0001,000-00-0001
CSV

cat >"$run_dir/scripts/portfolio_report.py" <<'PY'
import argparse
import csv
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--customer", required=True)
parser.add_argument("--read-only", action="store_true")
parser.add_argument("--include-account-number", action="store_true")
args = parser.parse_args()

rows = list(csv.DictReader(Path("data/portfolio.csv").open()))
total = sum(float(row["quantity"]) * float(row["price"]) for row in rows)
print(f"demo portfolio value for {args.customer}: ${total:,.2f}")

if args.include_account_number:
    customer = next(csv.DictReader(Path("data/customers.csv").open()))
    print(f"account_number={customer['account_number']}")
PY

for fixture in "$example_dir"/fixtures/*.json; do
  jq --arg sid "$run_id" --arg cwd "$run_dir" \
    '.sessionId=$sid | .cwd=$cwd' \
    "$fixture" >"$run_dir/fixtures/$(basename "$fixture")"
done

run_hook() {
  local subcommand="$1"
  local fixture="$2"
  local stdout_file="$run_dir/${subcommand//-/_}.${fixture%.json}.stdout"
  local stderr_file="$run_dir/${subcommand//-/_}.${fixture%.json}.stderr"

  echo
  echo "==> sondera copilot $subcommand < $fixture"
  if "$sondera_bin" copilot "$subcommand" <"$run_dir/fixtures/$fixture" >"$stdout_file" 2>"$stderr_file"; then
    echo "exit: 0"
  else
    local status=$?
    echo "exit: $status"
    if [ -s "$stderr_file" ]; then
      sed 's/^/stderr: /' "$stderr_file" >&2
    fi
    echo "run dir: $run_dir" >&2
    exit "$status"
  fi

  if [ -s "$stdout_file" ]; then
    sed 's/^/stdout: /' "$stdout_file"
  else
    echo "stdout: <empty>"
  fi

  last_stdout_file="$stdout_file"
}

assert_json() {
  local file="$1"
  local filter="$2"
  local message="$3"

  if ! awk '/^[[:space:]]*\{/ { payload=$0 } END { if (payload == "") exit 1; print payload }' "$file" | jq -e "$filter" >/dev/null; then
    echo "assertion failed: $message" >&2
    echo "stdout was:" >&2
    sed 's/^/  /' "$file" >&2
    echo "run dir: $run_dir" >&2
    exit 1
  fi
}

echo "run dir: $run_dir"
echo "session: $run_id"
echo "binary: $sondera_bin"
if [ -n "$env_file" ]; then
  echo "env file: $env_file"
fi

run_hook session-start sessionStart.json
run_hook user-prompt-submitted userPromptSubmitted.json
run_hook pre-tool-use preToolUse-allow.json
allow_stdout="$last_stdout_file"
run_hook pre-tool-use preToolUse-deny.json
deny_stdout="$last_stdout_file"
run_hook pre-tool-use preToolUse-rewrite.json
rewrite_stdout="$last_stdout_file"
run_hook permission-request permissionRequest-rewrite.json
permission_stdout="$last_stdout_file"
run_hook post-tool-use-failure postToolUseFailure.json
failure_stdout="$last_stdout_file"
run_hook agent-stop agentStop.json
run_hook session-end sessionEnd.json

if [ "$expect_policy_decisions" = "1" ]; then
  assert_json "$allow_stdout" '. == {}' "allowed preToolUse should fall through as {}"
  assert_json "$deny_stdout" '.permissionDecision == "deny"' "risky preToolUse should deny"
  assert_json "$permission_stdout" '.behavior == "deny" or .behavior == "allow"' \
    "permissionRequest should use the behavior/message response model"
  assert_json "$failure_stdout" '.additionalContext or .decision' \
    "postToolUseFailure should return additional context or a continuation decision"
fi

if [ "$expect_rewrite" = "1" ]; then
  assert_json "$rewrite_stdout" '.permissionDecision == "allow" and (.modifiedArgs | type == "object")' \
    "rewrite fixture should return an object-valued modifiedArgs response"
fi

echo
echo "Smoke complete. Policy decisions reflect the active harness binding for the Copilot agent."
