// Command ssf inspects Shared Signals Framework Transmitters and the
// Security Event Tokens they issue, using SSFgo's Receiver checks.
//
//	ssf metadata https://tx.example.com
//	ssf verify -issuer https://tx.example.com -audience https://rp.example.com token.jwt
//	ssf decode -unverified < token.jwt
//
// metadata discovers a Transmitter as a Receiver does (SSF 1.0 §7.2) and
// prints its Transmitter Configuration Metadata, or why a Receiver would
// refuse it. verify checks a SET against the Transmitter's published keys
// and the issuer and audience given, as delivery does, and prints its
// header and claims. decode prints them without checking anything. The
// JSON printed has a "verified" member saying which of the two it is.
//
// Output escapes control and formatting characters — C0 and C1 controls,
// DEL, bidirectional overrides — so a SET cannot drive the terminal.
//
// Install it with:
//
//	go install github.com/idfoundry/ssfgo/cmd/ssf@latest
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// maxTokenBytes bounds a SET read from a file or standard input.
const maxTokenBytes = 1 << 20

// tokenEnv names the environment variable holding the access token
// verify -audience-per-stream reads a stream with.
const tokenEnv = "SSF_ACCESS_TOKEN"

const usage = `usage:
  ssf metadata [flags] ISSUER
  ssf verify -issuer ISSUER -audience AUDIENCE [flags] [TOKEN | FILE | -]
  ssf decode -unverified [TOKEN | FILE | -]

Flags may come before or after the argument. Run "ssf COMMAND -h" for a
command's flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil))
}

// cli is one invocation's input, output and HTTP client (nil for the
// Receiver's default).
type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	client         *http.Client
}

// run runs the command in args and returns the exit status: 0 on
// success, 1 when the check failed, 2 for a usage error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, client *http.Client) int {
	c := cli{stdin, stdout, stderr, client}
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "metadata":
		return c.metadata(args[1:])
	case "verify":
		return c.verify(args[1:])
	case "decode":
		return c.decode(args[1:])
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "ssf: unknown command %s\n\n%s", terminalSafe(strconv.Quote(args[0])), usage)
	return 2
}

// discovery holds the flags that shape how a Transmitter is discovered.
type discovery struct {
	metadataURL    string
	trustedOrigins stringList
	algorithms     string
	legacy         bool
	caFile         string
	timeout        time.Duration
}

func (d *discovery) register(fs *flag.FlagSet) {
	fs.StringVar(&d.metadataURL, "metadata-url", "", "fetch the metadata from this URL only, rather than the issuer's well-known locations")
	fs.Var(&d.trustedOrigins, "trusted-origin", "an origin besides the issuer's that may serve authenticated endpoints (repeatable)")
	fs.StringVar(&d.algorithms, "alg", "", "comma-separated signature algorithms to accept (default: receiver.RecommendedAlgorithms)")
	fs.BoolVar(&d.legacy, "legacy-subjects", false, "accept subjects in the forms CAEP and RISC used before SSF 1.0")
	fs.StringVar(&d.caFile, "ca-file", "", "a PEM file of CA certificates to trust besides the system's, such as a development Transmitter's")
	fs.DurationVar(&d.timeout, "timeout", 30*time.Second, "how long to wait for the Transmitter")
}

// receiver discovers the Transmitter for issuer as an SSFgo Receiver with
// audience would, registering every event family SSFgo implements. With
// perStream, it accepts per-stream audiences, reading streams with the
// access token in tokenEnv.
func (d *discovery) receiver(ctx context.Context, c cli, issuer, audience string, perStream bool) (*receiver.Receiver, error) {
	client, err := d.client(c.client)
	if err != nil {
		return nil, err
	}
	// Never sent unless perStream: no other check calls an authenticated
	// endpoint.
	token := "unused"
	if perStream {
		if token = os.Getenv(tokenEnv); token == "" {
			return nil, fmt.Errorf("-audience-per-stream reads the SET's stream from the Transmitter: set %s to an access token for its configuration endpoint", tokenEnv)
		}
	}
	registry := ssf.NewRegistry()
	for _, register := range []func(*ssf.Registry) error{caep.Register, risc.Register, scim.Register} {
		if err := register(registry); err != nil {
			return nil, err
		}
	}
	algorithms := receiver.RecommendedAlgorithms()
	if d.algorithms != "" {
		algorithms = nil
		for _, name := range strings.Split(d.algorithms, ",") {
			alg, err := ssf.ParseSignatureAlgorithm(strings.TrimSpace(name))
			if err != nil {
				return nil, err
			}
			algorithms = append(algorithms, alg)
		}
	}
	return receiver.New(ctx, receiver.Config{
		// The Receiver only inspects: it handles nothing and keeps no
		// state, so it needs no durable store.
		Assurance:            ssf.AssuranceDevelopment,
		Limits:               receiver.RecommendedLimits(),
		Issuer:               issuer,
		Audience:             audience,
		MetadataURL:          d.metadataURL,
		TrustedOrigins:       d.trustedOrigins,
		Registry:             registry,
		Algorithms:           algorithms,
		AcceptLegacySubjects: d.legacy,
		AudiencePerStream:    perStream,
		TokenSource:          receiver.StaticToken(token),
		ReplayStore:          memstore.NewReplayStore(),
		HTTPClient:           client,
		Logger:               slog.New(slog.DiscardHandler),
	})
}

// client returns base, or with caFile a client trusting its certificates
// too.
func (d *discovery) client(base *http.Client) (*http.Client, error) {
	if d.caFile == "" {
		return base, nil
	}
	pem, err := os.ReadFile(d.caFile)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificates", d.caFile)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport}, nil
}

func (c cli) metadata(args []string) int {
	fs := c.flags("metadata", "ISSUER")
	var d discovery
	d.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	// The audience is required, but discovery does not use it.
	rx, err := d.receiver(ctx, c, pos[0], "urn:ssfgo:cli", false)
	if err != nil {
		return c.fail(err)
	}
	if err := c.printJSON(rx.Metadata()); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintln(c.stderr, "accepted: the metadata names the issuer, its endpoints are https on trusted origins, and its signing keys were fetched")
	return 0
}

func (c cli) verify(args []string) int {
	fs := c.flags("verify", "-issuer ISSUER -audience AUDIENCE [TOKEN | FILE | -]")
	var d discovery
	d.register(fs)
	issuer := fs.String("issuer", "", "the Transmitter's issuer, which the SET's \"iss\" must equal (required)")
	audience := fs.String("audience", "", "the Receiver's audience, which the SET's \"aud\" must contain (required)")
	perStream := fs.Bool("audience-per-stream", false, "also accept \"aud\" naming one of the Receiver's streams as AUDIENCE/STREAM_ID, reading the stream with the access token in "+tokenEnv)
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if *issuer == "" || *audience == "" || len(pos) > 1 {
		fs.Usage()
		return 2
	}
	token, err := c.readToken(first(pos))
	if err != nil {
		return c.fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	rx, err := d.receiver(ctx, c, *issuer, *audience, *perStream)
	if err != nil {
		return c.fail(err)
	}
	set, err := rx.Verify(ctx, token)
	if err != nil {
		return c.fail(err)
	}
	parts, err := decodeParts(token)
	if err != nil {
		return c.fail(err)
	}
	parts.Verified = true
	if err := c.printJSON(parts); err != nil {
		return c.fail(err)
	}
	line := fmt.Sprintf("verified: %q event %s about %s", set.JWTID, set.Event.EventType(), set.Subject.Format())
	_, _ = fmt.Fprintln(c.stderr, terminalSafe(line))
	return 0
}

func (c cli) decode(args []string) int {
	fs := c.flags("decode", "-unverified [TOKEN | FILE | -]")
	unverified := fs.Bool("unverified", false, "confirm that the SET is to be printed without checking its signature or claims (required)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if !*unverified {
		_, _ = fmt.Fprintln(c.stderr, `ssf decode: decode checks nothing, so it needs -unverified; "ssf verify" checks a SET`)
		return 2
	}
	if len(pos) > 1 {
		fs.Usage()
		return 2
	}
	token, err := c.readToken(first(pos))
	if err != nil {
		return c.fail(err)
	}
	parts, err := decodeParts(token)
	if err != nil {
		return c.fail(err)
	}
	if err := c.printJSON(parts); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintln(c.stderr, "NOT VERIFIED: neither the signature nor any claim was checked")
	return 0
}

func (c cli) flags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet("ssf "+name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(c.stderr, "usage: ssf %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses args with fs, allowing flags after the positional
// arguments, which it returns. Everything after "--" is positional.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) < len(args) && args[len(args)-len(rest)-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos, args = append(pos, rest[0]), rest[1:]
	}
}

func first(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func (c cli) fail(err error) int {
	// Errors from the ssf package carry its name already.
	_, _ = fmt.Fprintln(c.stderr, "ssf:", terminalSafe(strings.TrimPrefix(err.Error(), "ssf: ")))
	return 1
}

func (c cli) printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.stdout, "%s\n", terminalSafe(string(out)))
	return err
}

// terminalSafe escapes, as JSON does, what a terminal would act on rather
// than show: controls other than newline and tab, DEL, C1 controls,
// formatting characters such as bidirectional overrides, and invalid
// UTF-8. JSON keeps its meaning, as such characters can only be in its
// strings.
func terminalSafe(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError:
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				b.WriteString(`\ufffd`)
				continue
			}
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r):
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// readToken returns the SET given as arg: a file holding it, if one has
// that name, otherwise the token itself; or, for "-" or no argument,
// standard input.
func (c cli) readToken(arg string) (string, error) {
	var r io.Reader
	_, statErr := os.Stat(arg) //nolint:gosec // G703: the user names the file to read
	switch {
	case arg == "" || arg == "-":
		r = c.stdin
	case statErr != nil && strings.Count(arg, ".") == 2 && !strings.ContainsAny(arg, "/\\"):
		return arg, nil
	default:
		f, err := os.Open(arg) //nolint:gosec // G304: the user names the file to read
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxTokenBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxTokenBytes {
		return "", fmt.Errorf("the SET is over %d bytes", maxTokenBytes)
	}
	return string(bytes.TrimSpace(b)), nil
}

// tokenParts is a SET's JWS header and claims, as JSON, and whether they
// were verified.
type tokenParts struct {
	Verified bool            `json:"verified"`
	Header   json.RawMessage `json:"header"`
	Claims   json.RawMessage `json:"claims"`
}

// decodeParts splits a compact JWS and decodes its header and payload,
// checking only that each is a JSON object.
func decodeParts(token string) (tokenParts, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenParts{}, errors.New("the SET is not a compact JWS (three dot-separated parts)")
	}
	var out [2]json.RawMessage
	for i, name := range []string{"header", "claims"} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return tokenParts{}, fmt.Errorf("the SET's %s is not base64url: %w", name, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(b, &obj); err != nil {
			return tokenParts{}, fmt.Errorf("the SET's %s is not a JSON object: %w", name, err)
		}
		out[i] = b
	}
	return tokenParts{Header: out[0], Claims: out[1]}, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
