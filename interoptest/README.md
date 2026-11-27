# Interoperability tests

Tests of SSFgo against independent implementations, beyond what the
OpenID Foundation conformance suite ([../conformance](../conformance))
covers: the Receiver against [Keycloak](#keycloak)'s Transmitter, and the
Transmitter against [easyssf](#easyssf)'s Receiver, in Go and in Java.

[`interop-keycloak.yml`](../.github/workflows/interop-keycloak.yml) and
[`interop-easyssf.yml`](../.github/workflows/interop-easyssf.yml) run them
daily, on demand, and on pull requests that change them or the packages
they build from. Neither is a required check, since they depend on other
projects' releases; each has a badge in the top-level README. Each peer's version is pinned where Dependabot can see it —
Keycloak's in [`keycloak/Dockerfile`](keycloak/Dockerfile), a file that is
never built, easyssf's in [`easyssf/go.mod`](easyssf/go.mod) and
[`easyssf/java/pom.xml`](easyssf/java/pom.xml) — so Dependabot proposes
newer releases weekly, and the workflow runs on that pull request before
the pin moves.

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
  go test -count=1 -v -run TestKeycloak ./interoptest/keycloak
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

## easyssf

[`easyssf`](easyssf) runs [easyssf](https://easyssf.org), an open-source
SSF Receiver library, against an SSFgo Transmitter
(`ssftest.NewTransmitter`): easyssf-go 0.7.0 in-process, and
easyssf-receiver 0.7.0 for Java as a small program
([`easyssf/java`](easyssf/java)) the Go test drives over stdin and stdout.
It is its own Go module, using SSFgo's public API only, so that easyssf's
dependencies stay out of SSFgo's.

For each library and each delivery method, push and poll, the test checks
that the library:

- registers its own stream through the stream management API, with the
  delivery method asked for;
- requests a verification event with a `state` of its own, and accepts
  the one the Transmitter sends;
- is handed CAEP session-revoked and RISC account-disabled, verified,
  about the right subject;
- deletes its stream when it stops.

The Java program serves no HTTPS of its own: the Go test serves the push
endpoint, as an application's web framework would, and hands each request
to easyssf's push handler (`SsfPushHandler.handle`).

### Running it locally

easyssf-go needs nothing but Go, so `go test` runs it; the Java half
needs Java 21 and Maven, and is skipped unless `EASYSSF_JAVA` names the
built program:

```sh
cd interoptest/easyssf
go test -count=1 -v -run TestEasySSFGo .

(cd java && mvn -B -q compile dependency:copy-dependencies)
EASYSSF_JAVA=$PWD/java go test -count=1 -v -run TestEasySSFJava .
```

### What easyssf does that isn't obvious

- **Its own revocation handler.** session-revoked about a subject with no
  `sid` or `sub` — an email address, say — is handed to the application
  but logs a warning that no tokens were revoked.
- **Verification** must have an `opaque` `sub_id` naming the stream (SSF
  1.0 §8.1.4.1), and its `state` must be one the library is waiting for;
  a verification event without a `state` is accepted.
- **Streams it creates** are reused on the next start, by the same
  credentials, and deleted on shutdown only when asked
  (`stream.delete-on-shutdown`, `setDeleteOnShutdown`), which the test
  does.
