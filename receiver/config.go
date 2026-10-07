package receiver

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/assurance"
	"github.com/idfoundry/ssfgo/storage"
)

// Config configures a Receiver. Every field without a documented default
// is required.
type Config struct {
	// Issuer is the Transmitter's issuer identifier. Its metadata is
	// fetched from the well-known location SSF 1.0 §7.2 derives from it —
	// or, if that is not found, from the issuer with that path appended,
	// where Transmitters built on OpenID Providers often publish it, then
	// from RISC's location (SSF 1.0 §7.2.2) — and must name exactly this
	// issuer.
	Issuer string

	// MetadataURL, if set, is the only location the Transmitter's
	// metadata is fetched from, for a Transmitter that publishes it
	// elsewhere. It must be https; the metadata must still name Issuer.
	// Optional.
	MetadataURL string

	// Audience is the Receiver's own audience value: every stream it
	// creates must list it in "aud", and every SET must be addressed to
	// it.
	Audience string

	// Registry holds the event types the Receiver understands. Streams
	// request them by default, and a SET of any other type is rejected.
	Registry *ssf.Registry

	// Algorithms lists the SET signature algorithms accepted. The CAEP
	// Interoperability Profile §2.6 uses RS256.
	Algorithms []ssf.SignatureAlgorithm

	// TokenSource supplies access tokens for the Transmitter's APIs.
	TokenSource TokenSource

	// ReplayStore records processed SETs, so redelivered ones are
	// acknowledged without being handled twice.
	ReplayStore storage.ReplayStore

	// Assurance is the deployment the Receiver is for. Required. Under
	// ssf.AssuranceProduction, ReplayStore must declare itself durable
	// (storage.Capabilities) — an in-memory one forgets on restart, and
	// SETs handled before it are accepted again — and Issuer and
	// MetadataURL must not be loopback hosts.
	Assurance ssf.Assurance

	// HorizontallyScaled declares that several Receiver instances share
	// ReplayStore. Under ssf.AssuranceProduction, it must then declare
	// itself consistent across instances.
	HorizontallyScaled bool

	// Limits bound how old a SET, and how old the Transmitter's keys, the
	// Receiver accepts. Required: RecommendedLimits is the usual choice.
	Limits Limits

	// CheckMetadata, if set, vets the Transmitter Configuration Metadata
	// New fetches; New fails with its error. It lets a profile refuse a
	// Transmitter that does not meet it — for example
	// caep/interop.CheckTransmitterMetadata. Optional.
	CheckMetadata func(ssf.TransmitterMetadata) error

	// SubjectMembers lists the complex-subject members, beyond those
	// SSF 1.0 §3.3 defines, that the application processes. A Transmitter
	// may declare members critical (critical_subject_members); SSF 1.0
	// §3.6 requires discarding any event whose subject has a critical
	// member the Receiver cannot process. The §3.3 members — user,
	// device, session, application, tenant, org_unit, group — are parsed
	// and handed to handlers, so they always count as processed; list
	// any other member here only if handlers act on it. Optional.
	SubjectMembers []string

	// TrustedOrigins lists origins ("https://host" or "https://host:port")
	// besides the issuer's own to which the Receiver may send its access
	// token. By default every endpoint it authenticates to — those in the
	// Transmitter's metadata and a stream's poll endpoint — must be on the
	// issuer's origin, so neither the metadata nor a stream configuration
	// can steer the token to another host. jwks_uri is fetched without
	// credentials and may be on any https host. Optional.
	TrustedOrigins []string

	// AcceptLegacySubjects opts in to SETs from Transmitters that predate
	// SSF 1.0: a SET without "sub_id" whose event carries a "subject"
	// member (SSF 1.0 §3.1.1), and subject identifiers naming their format
	// in Google's "subject_type" (RISC 1.0 §3.1). Off by default; enable it
	// only for a Transmitter known to need it.
	AcceptLegacySubjects bool

	// HTTPClient calls the Transmitter. Defaults to a client with a
	// 30-second timeout, long enough for a long poll. Whichever client is
	// used, the Receiver follows only redirects to https URLs.
	HTTPClient *http.Client

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time

	// Logger receives delivery problems that are reported to the
	// Transmitter rather than to the caller. Defaults to slog.Default().
	Logger *slog.Logger

	// Hooks observe the Receiver, to feed metrics or traces. Optional.
	Hooks Hooks
}

// Limits bound how long the Receiver trusts what it has seen. Each must
// be set: there are no implicit defaults, and RecommendedLimits gives
// starting values.
type Limits struct {
	// ReplayWindow is how long after its "iat" a SET is accepted, and how
	// long a processed SET is remembered to reject replays. A SET older
	// than this is rejected, so a captured SET cannot be replayed once its
	// record expires; SETs held on a paused stream for longer are lost.
	// Positive, at most MaxReplayWindow.
	ReplayWindow time.Duration

	// KeyMaxAge is how long the Transmitter's JWKS is used before it is
	// fetched again, so a retired key stops being trusted. A SET signed
	// with an unknown key also triggers a fetch, at most once a minute.
	// Positive.
	KeyMaxAge time.Duration

	// MaxClockSkew is how far in the future a SET's "iat" and "nbf" may
	// be. Zero allows none; it may not be negative.
	MaxClockSkew time.Duration
}

// MaxReplayWindow bounds Limits.ReplayWindow, so the times computed from
// it stay representable.
const MaxReplayWindow = 365 * 24 * time.Hour

// RecommendedLimits returns starting values for Limits. None is a
// specification requirement; each is this package's operational choice:
//
//   - ReplayWindow 7 days: longer than a stream is usually paused or a
//     Receiver down, so held SETs are still accepted when it resumes,
//     while the replay store stays bounded. RFC 8417 §4.1 leaves replay
//     detection to the recipient.
//   - KeyMaxAge 24 hours: a retired key stops being trusted within a day
//     even if no SET names an unknown key, which triggers a refetch
//     anyway.
//   - MaxClockSkew 1 minute: tolerates ordinary clock drift between the
//     Transmitter and the Receiver without accepting SETs dated well
//     into the future.
func RecommendedLimits() Limits {
	return Limits{ReplayWindow: 7 * 24 * time.Hour, KeyMaxAge: 24 * time.Hour, MaxClockSkew: time.Minute}
}

func (l Limits) errors() []error {
	var errs []error
	if l.ReplayWindow <= 0 || l.ReplayWindow > MaxReplayWindow {
		errs = append(errs, fmt.Errorf("Limits.ReplayWindow must be positive and at most %v (RecommendedLimits gives starting values)", MaxReplayWindow))
	}
	if l.KeyMaxAge <= 0 {
		errs = append(errs, errors.New("Limits.KeyMaxAge must be positive"))
	}
	if l.MaxClockSkew < 0 {
		errs = append(errs, errors.New("Limits.MaxClockSkew must not be negative"))
	}
	return errs
}

func (c *Config) validate() error {
	errs := c.Limits.errors()
	var keys []assurance.Key
	if cc, ok := c.TokenSource.(*ClientCredentials); ok && cc.AuthMethod == PrivateKeyJWT {
		keys = append(keys, assurance.Key{Field: "TokenSource.SigningKey", Custody: assurance.CustodyOf(cc.SigningKey, cc.SigningKeyCustody)})
	}
	errs = append(errs, assurance.Check(c.Assurance, c.HorizontallyScaled, assurance.Deps{
		Stores: []assurance.Store{{Field: "ReplayStore", Store: c.ReplayStore}},
		URLs:   []assurance.URL{{Field: "Issuer", Value: c.Issuer}, {Field: "MetadataURL", Value: c.MetadataURL}},
		Keys:   keys,
	})...)
	if err := ssf.ValidateIssuer(c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if c.Audience == "" {
		errs = append(errs, errors.New("an Audience is required"))
	}
	if c.Registry == nil {
		errs = append(errs, errors.New("a Registry is required"))
	}
	if len(c.Algorithms) == 0 {
		errs = append(errs, errors.New("at least one accepted algorithm is required"))
	}
	for _, a := range c.Algorithms {
		if !a.IsValid() {
			errs = append(errs, fmt.Errorf("invalid algorithm %v", a))
		}
	}
	if c.TokenSource == nil {
		errs = append(errs, errors.New("a TokenSource is required"))
	}
	if c.ReplayStore == nil {
		errs = append(errs, errors.New("a ReplayStore is required"))
	}
	if c.MetadataURL != "" {
		if u, err := url.Parse(c.MetadataURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("MetadataURL: %q is not an https URL", c.MetadataURL))
		}
	}
	for _, o := range c.TrustedOrigins {
		if u, err := url.Parse(o); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("TrustedOrigins: %q is not an https origin", o))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("receiver: invalid config: %w", err)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	c.HTTPClient = httpsOnlyRedirects(c.HTTPClient)
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}
