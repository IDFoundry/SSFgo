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
// header and claims. decode prints them without checking anything.
//
// Install it with:
//
//	go install github.com/idfoundry/ssfgo/cmd/ssf@latest
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// maxTokenBytes bounds a SET read from a file or standard input.
const maxTokenBytes = 1 << 20

const usage = `usage:
  ssf metadata [flags] ISSUER
  ssf verify -issuer ISSUER -audience AUDIENCE [flags] [TOKEN | FILE | -]
  ssf decode -unverified [TOKEN | FILE | -]

Run "ssf COMMAND -h" for a command's flags.
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
	_, _ = fmt.Fprintf(stderr, "ssf: unknown command %q\n\n%s", args[0], usage)
	return 2
}

// discovery holds the flags that shape how a Transmitter is discovered.
type discovery struct {
	metadataURL    string
	trustedOrigins stringList
	algorithms     string
	legacy         bool
	timeout        time.Duration
}

func (d *discovery) register(fs *flag.FlagSet) {
	fs.StringVar(&d.metadataURL, "metadata-url", "", "fetch the metadata from this URL only, rather than the issuer's well-known locations")
	fs.Var(&d.trustedOrigins, "trusted-origin", "an origin besides the issuer's that may serve authenticated endpoints (repeatable)")
	fs.StringVar(&d.algorithms, "alg", "", "comma-separated signature algorithms to accept (default: receiver.RecommendedAlgorithms)")
	fs.BoolVar(&d.legacy, "legacy-subjects", false, "accept subjects in the forms CAEP and RISC used before SSF 1.0")
	fs.DurationVar(&d.timeout, "timeout", 30*time.Second, "how long to wait for the Transmitter")
}

// receiver discovers the Transmitter for issuer as an SSFgo Receiver with
// audience would, registering every event family SSFgo implements.
func (d *discovery) receiver(ctx context.Context, c cli, issuer, audience string) (*receiver.Receiver, error) {
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
		// Never sent: neither command calls an authenticated endpoint.
		TokenSource: receiver.StaticToken("unused"),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  c.client,
		Logger:      slog.New(slog.DiscardHandler),
	})
}

func (c cli) metadata(args []string) int {
	fs := c.flags("metadata", "ISSUER")
	var d discovery
	d.register(fs)
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	// The audience is required, but discovery does not use it.
	rx, err := d.receiver(ctx, c, fs.Arg(0), "urn:ssfgo:cli")
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
	if fs.Parse(args) != nil {
		return 2
	}
	if *issuer == "" || *audience == "" || fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	token, err := c.readToken(fs.Arg(0))
	if err != nil {
		return c.fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	rx, err := d.receiver(ctx, c, *issuer, *audience)
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
	if err := c.printJSON(parts); err != nil {
		return c.fail(err)
	}
	_, _ = fmt.Fprintf(c.stderr, "verified: %s event %s about %s\n", set.JWTID, set.Event.EventType(), set.Subject.Format())
	return 0
}

func (c cli) decode(args []string) int {
	fs := c.flags("decode", "-unverified [TOKEN | FILE | -]")
	unverified := fs.Bool("unverified", false, "confirm that the SET is to be printed without checking its signature or claims (required)")
	if fs.Parse(args) != nil {
		return 2
	}
	if !*unverified {
		_, _ = fmt.Fprintln(c.stderr, `ssf decode: decode checks nothing, so it needs -unverified; "ssf verify" checks a SET`)
		return 2
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	token, err := c.readToken(fs.Arg(0))
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

func (c cli) fail(err error) int {
	_, _ = fmt.Fprintln(c.stderr, "ssf:", err)
	return 1
}

func (c cli) printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.stdout, "%s\n", out)
	return err
}

// readToken returns the SET given as arg: the token itself, a file
// holding it, or, for "-" or no argument, standard input.
func (c cli) readToken(arg string) (string, error) {
	var r io.Reader
	switch {
	case arg == "" || arg == "-":
		r = c.stdin
	case strings.Count(arg, ".") == 2 && !strings.ContainsAny(arg, "/\\"):
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

// tokenParts is a SET's JWS header and claims, as JSON.
type tokenParts struct {
	Header json.RawMessage `json:"header"`
	Claims json.RawMessage `json:"claims"`
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
