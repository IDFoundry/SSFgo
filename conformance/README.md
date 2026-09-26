# Conformance

SSFgo's correctness bar is the OpenID Foundation conformance suite. As of
September 2026 every SSF test plan is labelled "alpha — not currently part
of the certification program", so these are self-run results, not
certification.

## Transmitter

[`cmd/conformance-transmitter`](../cmd/conformance-transmitter) runs an
SSFgo Transmitter with in-memory storage, a freshly generated RS256 key, a
self-signed TLS certificate, and a minimal client-credentials OAuth server
for the suite to obtain access tokens from. The OAuth server is test
scaffolding, not part of the library.

[`transmitter/run.sh`](transmitter/run.sh) builds and starts it, runs one
test plan variant against a local suite, and stops it:

```bash
# once, in a checkout of https://gitlab.com/openid/conformance-suite
docker compose -f docker-compose-prebuilt.yml up -d
pip install -r scripts/requirements.txt

# from this repo: [static|dynamic] [poll|push] [module,module,...]
./conformance/transmitter/run.sh dynamic poll
```

The suite reaches the harness at `https://host.docker.internal:9443/ssfgo`
(Docker Desktop defines that hostname; on Linux add the host-gateway
mapping FAPIgo's `suite-host-gateway.override.yml` uses). Set `PLAN` to run
a plan other than `openid-ssf-transmitter-caep-test-plan`, for example
`PLAN='openid-ssf-transmitter-test-plan[ssf_profile=default]'`.

### Results — v0.3 (full CAEP Interop Transmitter plan)

Run 2026-09-26 against the suite's `latest` prebuilt image. Besides the
Transmitter, the harness plays the operator the CAEP Interop event test
asks for ("trigger these events on the transmitter"): about two seconds
after each successful verification request it emits the profile's
session-revoked, credential-change and device-compliance-change events,
using both the `iss_sub` and `email` subject formats (§2.5).

**CAEP Interop Transmitter plan** — every module, every variant:

| Module | static · poll | static · push | dynamic · poll | dynamic · push |
|---|---|---|---|---|
| openid-ssf-transmitter-metadata | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-stream-control-happy-path | PASSED | PASSED | PASSED | PASSED |
| …-error-create-stream-with-broken-input | PASSED | PASSED | PASSED | PASSED |
| …-error-create-stream-with-invalid-token | PASSED | PASSED | PASSED | PASSED |
| …-error-create-stream-with-duplicate-config | PASSED | PASSED | PASSED | PASSED |
| …-error-read-stream-with-invalid-token | PASSED | PASSED | PASSED | PASSED |
| …-error-read-unknown-stream | PASSED | PASSED | PASSED | PASSED |
| …-error-delete-stream-with-invalid-token | PASSED | PASSED | PASSED | PASSED |
| …-error-delete-unknown-stream | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-transmitter-stream-verification-poll-only | PASSED¹ | — | PASSED | — |
| openid-ssf-transmitter-stream-verification-poll-and-ack | PASSED | — | PASSED | — |
| openid-ssf-transmitter-stream-verification-ack-only | PASSED | — | PASSED | — |
| openid-ssf-transmitter-stream-verification-push | — | PASSED | — | PASSED |
| openid-ssf-transmitter-stream-verification-error-push-no-auth | — | PASSED | — | PASSED |
| **openid-ssf-transmitter-stream-caep-interop** | **PASSED** | **PASSED** | **PASSED** | **PASSED** |

"—": the suite only runs that module for the other delivery method.

¹ Failed once in the full-plan run because the suite could not connect to
the harness at all ("Connect to https://host.docker.internal:9443 failed:
Connect timed out" fetching the JWKS, before any SSF request), then passed
in three consecutive reruns. A Docker Desktop networking hiccup, not a
protocol failure; recorded here rather than hidden.

**Base SSF Transmitter plan** — the modules the CAEP Interop plan omits
(dynamic auth, poll): update ×3, replace ×3 and subject control, all
PASSED.
