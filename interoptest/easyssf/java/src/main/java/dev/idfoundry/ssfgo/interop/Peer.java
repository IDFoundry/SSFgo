package dev.idfoundry.ssfgo.interop;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.easyssf.core.stream.SsfStreamConfiguration;
import org.easyssf.receiver.event.SsfEventHandler;
import org.easyssf.receiver.http.JdkSsfHttpClient;
import org.easyssf.receiver.http.SsfHttpClient;
import org.easyssf.receiver.poll.SsfPoller;
import org.easyssf.receiver.push.SsfPushHandler;
import org.easyssf.receiver.push.SsfPushResponse;
import org.easyssf.receiver.set.InMemorySsfJtiDedupStore;
import org.easyssf.receiver.set.NimbusSsfSetVerifier;
import org.easyssf.receiver.set.SsfSetProcessor;
import org.easyssf.receiver.stream.SsfReceiverStream;
import org.easyssf.receiver.stream.SsfStreamClient;
import org.easyssf.receiver.stream.SsfStreamRegistrar;
import org.easyssf.receiver.stream.SsfStreamVerification;
import org.easyssf.receiver.transmitter.SsfTransmitterMetadataResolver;
import org.easyssf.receiver.transmitter.SsfTransmitterTokenProvider;

/**
 * easyssf's plain-Java Receiver, assembled as an application would, run
 * against an SSFgo Transmitter by ../../java_test.go.
 *
 * <p>The environment names the Transmitter: {@code SSF_ISSUER}, the access
 * token {@code SSF_TOKEN}, the PEM certificate to trust {@code SSF_CA}, the
 * delivery method {@code SSF_DELIVERY} ({@code push} or {@code poll}) and,
 * for push, {@code SSF_PUSH_URL} and {@code SSF_PUSH_AUTH}. The program
 * registers its own stream, then reads commands from stdin, one a line:
 * {@code verify} has it request a verification event, and
 * {@code push <base64 Authorization> <base64 body>} hands a pushed request
 * to easyssf's push handler (the Go test serves the HTTPS endpoint the
 * Transmitter pushes to, as an application's web framework would). It
 * writes JSON lines to stdout: {@code {"stream":…}} once registered,
 * {@code {"verified":true}} once a verification event was accepted,
 * {@code {"push_status":…}} for each push, an event line for each event its
 * handler is given, and {@code {"error":…}} on failure. It stops at the end
 * of stdin, deleting its stream.
 */
public final class Peer {

    private static final Duration WAIT = Duration.ofSeconds(30);

    private static final String VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification";

    private Peer() {
    }

    public static void main(String[] args) throws Exception {
        try {
            run();
        }
        catch (Exception ex) {
            out("{\"error\":" + quote(ex.toString()) + "}");
            System.exit(1);
        }
    }

    private static void run() throws Exception {
        String issuer = env("SSF_ISSUER");
        String token = env("SSF_TOKEN");
        String delivery = env("SSF_DELIVERY");

        HttpClient jdk = HttpClient.newBuilder()
            .sslContext(trusting(Path.of(env("SSF_CA"))))
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        SsfHttpClient http = new JdkSsfHttpClient(jdk, WAIT);
        SsfTransmitterMetadataResolver metadata = new SsfTransmitterMetadataResolver(issuer, null, http);
        SsfTransmitterTokenProvider tokens = () -> token;
        SsfReceiverStream stream = new SsfReceiverStream();

        NimbusSsfSetVerifier verifier = new NimbusSsfSetVerifier(issuer,
                () -> metadata.resolve().jwksUri().toString(), http);
        verifier.setExpectedAudiences(stream::getAudience);
        SsfStreamVerification verification = new SsfStreamVerification();
        verification.setStreamId(stream::getStreamId);

        SsfEventHandler handler = (event) -> {
            for (String type : event.eventTypes()) {
                if (!VERIFICATION.equals(type)) {
                    out("{\"type\":" + quote(type) + ",\"email\":" + quote(event.subjectFor(type).email())
                            + ",\"delivery\":" + quote(delivery) + "}");
                }
            }
        };
        SsfSetProcessor processor = new SsfSetProcessor(verifier, new InMemorySsfJtiDedupStore(1_000),
                List.of(handler));
        processor.setStreamVerification(verification);

        List<String> events = List.of("CaepSessionRevoked", "RiscAccountDisabled");
        SsfStreamConfiguration desired = switch (delivery) {
            case "push" -> SsfStreamConfiguration.push(URI.create(env("SSF_PUSH_URL")), env("SSF_PUSH_AUTH"), events,
                    "SSFgo interop");
            case "poll" -> SsfStreamConfiguration.poll(events, "SSFgo interop");
            default -> throw new IllegalArgumentException("SSF_DELIVERY must be push or poll, not " + delivery);
        };
        SsfStreamClient streamClient = new SsfStreamClient(http, tokens, metadata);
        SsfStreamRegistrar registrar = SsfStreamRegistrar.forManagedStream(streamClient, stream, desired);
        registrar.setDeleteOnShutdown(true);
        registrar.start();
        await(() -> registrar.getState() == SsfStreamRegistrar.State.REGISTERED,
                () -> "the stream was not registered: " + registrar.getLastError());
        out("{\"stream\":" + quote(stream.getStreamId()) + "}");

        SsfPoller poller = null;
        if ("poll".equals(delivery)) {
            poller = new SsfPoller(http, tokens, () -> stream.getConfiguration()
                .map(SsfStreamConfiguration::deliveryEndpointUrl)
                .orElse(null), processor);
            poller.setTransmitter(issuer);
            poller.setInterval(Duration.ofMillis(200));
            poller.start();
        }
        SsfPushHandler push = new SsfPushHandler(processor, "push".equals(delivery) ? env("SSF_PUSH_AUTH") : null);

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = in.readLine()) != null;) {
            String[] command = line.split(" ");
            switch (command[0]) {
                case "verify" -> {
                    verification.requestVerification(streamClient, stream.getStreamId());
                    // The verification event may arrive by push, through this loop,
                    // so wait for it elsewhere.
                    Thread.ofVirtual().start(() -> {
                        try {
                            await(() -> !verification.isPending(), () -> "the verification event was not accepted");
                            out("{\"verified\":true}");
                        }
                        catch (Exception ex) {
                            out("{\"error\":" + quote(ex.getMessage()) + "}");
                        }
                    });
                }
                case "push" -> {
                    Base64.Decoder b64 = Base64.getDecoder();
                    SsfPushResponse response = push.handle(new String(b64.decode(command[1]), StandardCharsets.UTF_8),
                            b64.decode(command[2]));
                    out("{\"push_status\":" + response.status() + ",\"push_body\":"
                            + quote(response.body() == null ? "" : response.body()) + "}");
                }
                default -> throw new IllegalArgumentException("unknown command " + command[0]);
            }
        }
        if (poller != null) {
            poller.stop();
        }
        registrar.stop();
    }

    /** An SSL context that trusts only the certificate in the PEM file. */
    private static SSLContext trusting(Path pem) throws Exception {
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        try (InputStream cert = Files.newInputStream(pem)) {
            trust.setCertificateEntry("transmitter", CertificateFactory.getInstance("X.509").generateCertificate(cert));
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return context;
    }

    private static void await(BooleanSupplier condition, java.util.function.Supplier<String> failure)
            throws InterruptedException {
        Instant deadline = Instant.now().plus(WAIT);
        while (!condition.getAsBoolean()) {
            if (Instant.now().isAfter(deadline)) {
                throw new IllegalStateException(failure.get());
            }
            Thread.sleep(50);
        }
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " is not set");
        }
        return value;
    }

    private static synchronized void out(String line) {
        System.out.println(line);
        System.out.flush();
    }

    /** A JSON string literal. */
    private static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }

}
