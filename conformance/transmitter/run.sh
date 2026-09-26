#!/usr/bin/env bash
# Runs an OIDF SSF Transmitter test plan against cmd/conformance-transmitter.
#
# Usage: run.sh [static|dynamic] [poll|push] [module,module,...]
#
# Prerequisites:
#   - the OIDF conformance suite running locally, e.g. from a checkout:
#       docker compose -f docker-compose-prebuilt.yml up -d
#   - its script dependencies: pip install -r scripts/requirements.txt
#
# Environment:
#   CONFORMANCE_SUITE_CHECKOUT  suite checkout (default ../conformance-suite next to this repo)
#   CONFORMANCE_SERVER          suite URL (default https://localhost.emobix.co.uk:8443/)
#   CONFORMANCE_TOKEN           suite API token; without one the suite is driven in dev mode
#   PYTHON                      interpreter with the suite's requirements (default python3)
#   PLAN                        test plan (default openid-ssf-transmitter-caep-test-plan)
#   PORT                        harness port (default 9443)
#   WORKDIR                     where logs and results go (default a temp dir)
set -euo pipefail

auth="${1:-dynamic}"
delivery="${2:-poll}"
modules="${3:-}"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
suite="${CONFORMANCE_SUITE_CHECKOUT:-$repo/../conformance-suite}"
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443/}"
[[ -z "${CONFORMANCE_TOKEN:-}" ]] && export CONFORMANCE_DEV_MODE=1
python="${PYTHON:-python3}"
plan="${PLAN:-openid-ssf-transmitter-caep-test-plan}"
port="${PORT:-9443}"
workdir="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$workdir"

# The suite reaches the harness on the host through host.docker.internal.
origin="https://host.docker.internal:$port"
issuer_path="/ssfgo"
static_token="ssfgo-static-$RANDOM$RANDOM"

variants="[ssf_delivery_mode=$delivery][ssf_server_metadata=discovery][ssf_auth_mode=$auth]"
case "$auth" in
static) ;;
dynamic) variants="$variants[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_basic]" ;;
*) echo "auth must be static or dynamic" >&2; exit 2 ;;
esac

config="$workdir/config-$auth.json"
sed -e "s#{ORIGIN}#$origin#g" -e "s#{ISSUER_PATH}#$issuer_path#g" -e "s#{STATIC_TOKEN}#$static_token#g" \
	"$repo/conformance/transmitter/config-$auth.json" >"$config"

(cd "$repo" && go build -o "$workdir/conformance-transmitter" ./cmd/conformance-transmitter)
"$workdir/conformance-transmitter" -addr ":$port" -issuer "$origin$issuer_path" -static-token "$static_token" -insecure-push-tls \
	>"$workdir/transmitter.log" 2>&1 &
harness=$!
trap 'kill $harness 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
	curl -sk --max-time 2 -o /dev/null "https://localhost:$port$issuer_path/ssf/jwks.json" && break
	sleep 0.2
done

spec="$plan$variants"
[[ -n "$modules" ]] && spec="$spec:$modules"
echo "running $spec (logs in $workdir)"
cd "$suite"
"$python" scripts/run-test-plan.py --export-dir "$workdir" "$spec" "$config" 2>&1 | tee "$workdir/run-test-plan.log"
