#!/usr/bin/env bash
# Runs SSFgo's full conformance matrix against a locally running OIDF
# conformance suite and prints one summary:
#
#   Transmitter — CAEP Interop plan, {static, dynamic} x {poll, push}
#   Receiver    — CAEP Interop plan, {static, dynamic} x {poll, push}
#               — dynamic auth with client_secret_post, client_secret_jwt
#                 and private_key_jwt
#               — base plan supported-events test (CAEP + RISC), poll and push
#
# A Transmitter variant that fails is retried once: the suite occasionally
# cannot connect to the harness at all (see conformance/README.md).
# openid-ssf-receiver-stream-caep-interop is an expected failure — a
# conformance-suite defect documented in conformance/README.md.
#
# Prerequisites: the suite running (docker compose -f
# docker-compose-prebuilt.yml up -d, plus suite-host-gateway.override.yml on
# Linux) and its script requirements installed for $PYTHON.
#
# Environment: CONFORMANCE_SUITE_CHECKOUT, CONFORMANCE_SERVER, PYTHON,
# WORKDIR (default: a temp dir), ONLY (transmitter or receiver: run one
# half of the matrix).
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443/}"
workdir="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$workdir"
summary="$workdir/summary.txt"
: >"$summary"
failures=0

echo "waiting for the conformance suite at $CONFORMANCE_SERVER"
for _ in $(seq 1 60); do
	curl -sk --max-time 5 -f -o /dev/null "${CONFORMANCE_SERVER}api/runner/available" && break
	sleep 5
done

record() { # name status
	local name="$1" status="$2"
	printf '%-45s %s\n' "$name" "$status" | tee -a "$summary"
	[[ "$status" == PASSED ]] || failures=$((failures + 1))
	return 0
}

only="${ONLY:-}"

# --- Transmitter ---
[[ "$only" == receiver ]] || for auth in static dynamic; do
	for delivery in poll push; do
		name="transmitter $auth/$delivery"
		status=FAILED
		for attempt in 1 2; do
			log="$workdir/tx-$auth-$delivery-$attempt.log"
			if WORKDIR="$workdir/tx-$auth-$delivery-$attempt" "$repo/conformance/transmitter/run.sh" "$auth" "$delivery" >"$log" 2>&1; then
				status=PASSED
				break
			fi
			echo "$name: attempt $attempt failed (see $log)"
		done
		record "$name" "$status"
	done
done

# --- Receiver ---
if [[ "$only" == transmitter ]]; then
	echo
	echo "=== SSFgo conformance summary ($failures failing) ==="
	cat "$summary"
	exit $((failures > 0))
fi
receiver="$workdir/conformance-receiver"
(cd "$repo" && go build -o "$receiver" ./cmd/conformance-receiver) || exit 1
run_receiver() { # name, driver args...
	local name="$1"
	shift
	local slug="${name//[ \/]/-}"
	local log="$workdir/rx-$slug.log"
	if "$receiver" -suite "$CONFORMANCE_SERVER" "$@" >"$log" 2>&1; then
		record "receiver $name" PASSED
	else
		record "receiver $name" "FAILED (see $log)"
	fi
	grep -E '^(PASSED|FAILED|WARNING|ERROR|TIMEOUT|INTERRUPTED|REVIEW|SKIPPED)' "$log" | sed 's/^/    /'
	return 0
}
expected=openid-ssf-receiver-stream-caep-interop
for auth in static dynamic; do
	for delivery in poll push; do
		run_receiver "$auth/$delivery" -auth "$auth" -delivery "$delivery" -expected-failures "$expected"
	done
done
for ca in client_secret_post client_secret_jwt private_key_jwt; do
	run_receiver "dynamic/poll/$ca" -auth dynamic -delivery poll -client-auth "$ca" \
		-modules openid-ssf-receiver-stream-create-delete,openid-ssf-receiver-stream-verification
done
for delivery in poll push; do
	run_receiver "base supported-events/$delivery" -plan openid-ssf-receiver-test-plan \
		-variant ssf_profile=default -subjects email -delivery "$delivery" \
		-modules openid-ssf-receiver-stream-supported-events
done

echo
echo "=== SSFgo conformance summary ($failures failing) ==="
cat "$summary"
exit $((failures > 0))
