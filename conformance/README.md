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

The harness also turns on SSFgo's optional features the suite can
observe: a Transmitter-initiated verification event on every new stream,
which the suite logs as accepted, and a one-hour `inactivity_timeout`,
which it lists among the stream's optional fields.

[`transmitter/run.sh`](transmitter/run.sh) builds and starts it, runs one
test plan variant against a local suite, and stops it:

```bash
# once, in a checkout of https://gitlab.com/openid/conformance-suite
docker compose -f docker-compose-prebuilt.yml up -d
# the suite's script dependencies, pinned with hashes by this repo
pip install --require-hashes -r /path/to/SSFgo/conformance/scripts/requirements.txt

# from this repo: [static|dynamic] [poll|push] [module,module,...]
./conformance/transmitter/run.sh dynamic poll
```

The suite reaches the harness at `https://host.docker.internal:9443/ssfgo`
(Docker Desktop defines that hostname; on Linux also pass
[`scripts/suite-host-gateway.override.yml`](scripts/suite-host-gateway.override.yml)
to `docker compose -f`, which maps it to the host). Set `PLAN` to run
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

## Receiver

In a Receiver plan the suite emulates a Transmitter per test module and
waits for the Receiver to act. [`cmd/conformance-receiver`](../cmd/conformance-receiver)
drives that: it creates the plan, and for each module reads the emulated
Transmitter's issuer and credentials from the suite API ("exposed
values"), then runs one SSFgo Receiver session — discover, create a
stream, read it and its status, request verification, take delivery until
events stop, delete the stream. Push deliveries arrive on a self-signed
HTTPS listener the suite reaches at `https://host.docker.internal:9444`.

```bash
# CAEP Interop plan: -auth static|dynamic, -delivery poll|push
go run ./cmd/conformance-receiver -auth dynamic -delivery push

# base plan's supported-events test (every CAEP and RISC event type)
go run ./cmd/conformance-receiver -plan openid-ssf-receiver-test-plan \
  -variant ssf_profile=default -subjects email \
  -modules openid-ssf-receiver-stream-supported-events
```

For the CAEP Interop plan the driver applies `interop.ApplyReceiver`, so
the suite's emulated Transmitter is itself held to the profile; it passes.

Dynamic auth uses `client_secret_basic` by default; `-client-auth` also
takes `client_secret_post`, `client_secret_jwt` and `private_key_jwt`
(the driver generates the key and registers its public JWKS in the plan
configuration). All four pass the create-delete and verification modules
(v0.5).

## Running everything

[`scripts/run-all.sh`](scripts/run-all.sh) runs the whole matrix — both
roles, every variant, every client authentication method — and prints one
summary, treating the documented suite defect below as expected.
`.github/workflows/conformance.yml` runs it daily and on demand.

### Results — v0.4

Run 2026-09-26 against the suite's `latest` prebuilt image.

**CAEP Interop Receiver plan:**

| Module | static · poll | static · push | dynamic · poll | dynamic · push |
|---|---|---|---|---|
| openid-ssf-receiver-stream-create-delete | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-receiver-stream-verification | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-receiver-unsolicited-stream-verification | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-receiver-stream-supported-events | PASSED | PASSED | PASSED | PASSED |
| openid-ssf-receiver-stream-caep-interop | FAILED² | FAILED² | FAILED² | FAILED² |

**Base SSF Receiver plan**, `openid-ssf-receiver-stream-supported-events`
with CAEP and RISC registered: PASSED for poll and push. Each run
delivered 23 distinct event types — verification, all 8 CAEP and all 14
RISC types — every one verified, handled and acknowledged.

² **Conformance suite defect, not an SSFgo one.**
`OIDSSFReceiverStreamCaepInteropTest.afterInitialStreamVerification`
sets `event_timestamp` from `System.currentTimeMillis()` (line 183, still
so on upstream master), so every CAEP event it generates carries a
timestamp in **milliseconds**, e.g. `1790407364112`. CAEP 1.0 §2 defines
`event_timestamp` as a JSON number of **seconds**, the suite's own
Transmitter-side check (`OIDSSFValidateCaepCommonOptionalFields`) says the
same, and the suite's supported-events test correctly uses
`Instant.now().getEpochSecond()`. SSFgo rejects the malformed SETs —
`invalid_request: NumericDate 1790407364112 is out of range` — as 400 on
push and in `setErrs` on poll, so the module records them as not
acknowledged. The one-line fix in the suite is
`Instant.now().getEpochSecond()`.

**Subjects for the base plan.** The supported-events test sends every
event about every configured subject, including RISC `identifier-changed`
and `identifier-recycled`, which RISC 1.0 §2.5/§2.6 restrict to `email` or
`phone_number` subjects. With an `iss_sub` subject configured, SSFgo
correctly rejects those two SETs; the base-plan run therefore configures an
email subject only. (The CAEP Interop plan requires both `email` and
`iss_sub`, and sends no RISC events.)
