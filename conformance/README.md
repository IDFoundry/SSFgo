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

### Results — v0.2 (stream management)

Run 2026-09-26 against the suite's `latest` prebuilt image.

**CAEP Interop Transmitter plan** — each module below passed in all four
variants: {static token, client credentials with `client_secret_basic`} ×
{poll, push}.

| Module | Result |
|---|---|
| openid-ssf-transmitter-metadata | PASSED |
| openid-ssf-stream-control-happy-path | PASSED |
| openid-ssf-stream-control-error-create-stream-with-broken-input | PASSED |
| openid-ssf-stream-control-error-create-stream-with-invalid-token | PASSED |
| openid-ssf-stream-control-error-create-stream-with-duplicate-config | PASSED |
| openid-ssf-stream-control-error-read-stream-with-invalid-token | PASSED |
| openid-ssf-stream-control-error-read-unknown-stream | PASSED |
| openid-ssf-stream-control-error-delete-stream-with-invalid-token | PASSED |
| openid-ssf-stream-control-error-delete-unknown-stream | PASSED |
| openid-ssf-transmitter-stream-verification-* | not yet: needs v0.3 delivery |
| openid-ssf-transmitter-stream-caep-interop | not yet: needs v0.3 delivery |

**Base SSF Transmitter plan** — the modules the CAEP Interop plan omits
(dynamic auth, poll):

| Module | Result |
|---|---|
| openid-ssf-stream-control-error-update-stream-with-invalid-token | PASSED |
| openid-ssf-stream-control-error-update-stream-with-invalid-body | PASSED |
| openid-ssf-stream-control-error-update-unknown-stream | PASSED |
| openid-ssf-stream-control-error-replace-stream-with-invalid-body | PASSED |
| openid-ssf-stream-control-error-replace-stream-with-invalid-token | PASSED |
| openid-ssf-stream-control-error-replace-unknown-stream | PASSED |
| openid-ssf-stream-subject-control | PASSED |

The verification modules poll the stream's `endpoint_url`, which v0.3
serves. Until then they fail, and after three consecutive failures the
suite's runner aborts the rest of the plan — pass a module list to
`run.sh` to run only what is implemented.
