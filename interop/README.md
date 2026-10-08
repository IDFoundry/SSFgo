# Interoperability tests

Tests of SSFgo against deployed implementations, beyond what the OpenID
Foundation conformance suite ([../conformance](../conformance)) covers.
Each is skipped unless pointed at a running peer, and
[`interop.yml`](../.github/workflows/interop.yml) runs them weekly, on
demand, and on pull requests that change them — not on every pull
request, since they depend on other projects' releases.

## Keycloak

[`keycloak`](keycloak) runs an SSFgo Receiver against the SSF Transmitter
Keycloak 26.8 ships as an experimental feature. The test sets Keycloak up
through its admin API — a realm with the Transmitter enabled, a receiver
client, a user — creates a poll stream, verifies it, and checks that:

- logging out one session sends session-revoked for that session, which
  the `revocation` package turns into that session's tokens only;
- an administrator's "log out all sessions" sends session-revoked for
  the session `ALL`, which revokes every token of the user with
  `revocation.Options.AllSessions`;
- resetting a password sends credential-change, and disabling the user
  RISC account-disabled.

No SET may be rejected along the way.

### Running it locally

Keycloak must serve https, since the Receiver requires an https issuer:

```sh
mkdir -p /tmp/kc-certs
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout /tmp/kc-certs/tls.key -out /tmp/kc-certs/tls.crt
chmod 644 /tmp/kc-certs/tls.key
docker run --rm -d --name keycloak -p 8443:8443 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v /tmp/kc-certs:/opt/keycloak/conf/certs:ro \
  quay.io/keycloak/keycloak:26.8.0 start-dev --features=ssf \
  --https-certificate-file=/opt/keycloak/conf/certs/tls.crt \
  --https-certificate-key-file=/opt/keycloak/conf/certs/tls.key \
  --hostname=https://localhost:8443 --http-enabled=false

SSFGO_INTEROP_KEYCLOAK=https://localhost:8443 \
SSFGO_INTEROP_KEYCLOAK_CA=/tmp/kc-certs/tls.crt \
  go test -count=1 -v -run TestKeycloak ./interop/keycloak
```

`SSFGO_INTEROP_KEYCLOAK_ADMIN` and `SSFGO_INTEROP_KEYCLOAK_ADMIN_PASSWORD`
override the `admin`/`admin` bootstrap credentials. The test replaces the
realm `ssfgo-interop` and deletes it afterwards.

### What Keycloak does that isn't obvious

- **Per-stream audiences.** Unless the receiver client's
  `ssf.streamAudience` attribute is set, a stream's `aud` — and its SETs'
  — is `<client_id>/<stream_id>`. Configure the Receiver with the client
  ID as `Audience` and `AudiencePerStream`, or set the attribute to the
  Receiver's `Audience`.
- **All sessions.** session-revoked for every session of a user names the
  session `ALL`; set `revocation.Options.AllSessions` to `"ALL"`.
- **Account-disabled reasons** are Keycloak's own, such as
  `disabled-by-admin`; SSFgo accepts reasons RISC does not list.
- **Subjects.** Events reach a stream only for the client's default
  subjects: `ssf.defaultSubjects` `ALL`, or users added to the stream.
- **Scopes.** Stream management needs `ssf.manage`, reading and polling
  `ssf.read`; Keycloak creates both client scopes, and the receiver
  client must be given them.
- **Poll.** Requests return at once (no long polling), and `maxEvents: 0`
  counts as 1, so an acknowledgement-only poll returns a SET, which is
  delivered again on the next poll.
- **Verification** is sent when the Receiver asks for it, not on stream
  creation, unless `ssf.autoVerifyStream` is set.
- **stream-updated** carries `status` as an object rather than a string,
  which a strict Receiver rejects. Keycloak sends it only when a stream's
  status changes, which the test does not do.
