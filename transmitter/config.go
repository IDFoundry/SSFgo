package transmitter

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/storage"
)

// SigningKey is a key the Transmitter signs SETs with and publishes in its
// JWKS.
type SigningKey struct {
	Signer    crypto.Signer
	Algorithm ssf.SignatureAlgorithm
	// KeyID is the key's "kid". It is required, so Receivers can select
	// the right key during rotation.
	KeyID string
}

// Config configures a Transmitter. Every field without a documented
// default is required: SSFgo does not guess at deployment decisions.
type Config struct {
	// Issuer is the Transmitter's issuer identifier: an https URL with
	// no query or fragment. It may have a path, which lets several
	// Transmitters share a host (SSF 1.0 §7.2).
	Issuer string

	// SigningKeys are published in the JWKS. The first signs every SET;
	// the rest remain published so SETs signed before a rotation still
	// verify.
	SigningKeys []SigningKey

	// EventsSupported lists the event types this Transmitter can emit.
	// A stream delivers the intersection of these and the Receiver's
	// events_requested (SSF 1.0 §8.1.1).
	EventsSupported []ssf.EventType

	// DeliveryMethods lists the delivery methods Receivers may choose.
	DeliveryMethods []ssf.DeliveryMethod

	// DefaultSubjects is advertised in the metadata: whether new streams
	// start with every subject or none (SSF 1.0 §7.1).
	DefaultSubjects ssf.DefaultSubjects

	// Store persists streams.
	Store storage.StreamStore

	// Authorize resolves bearer tokens to Receivers.
	Authorize AuthorizeFunc

	// MultipleStreamsPerReceiver lets one Receiver create several
	// streams. When false, a second create request gets 409 Conflict
	// (SSF 1.0 §8.1.1.1).
	MultipleStreamsPerReceiver bool

	// MinVerificationInterval rate-limits verification requests per
	// stream (SSF 1.0 §8.1.1). It is advertised in whole seconds. Zero
	// disables the limit.
	MinVerificationInterval time.Duration

	// CriticalSubjectMembers lists complex-subject members Receivers must
	// understand (SSF 1.0 §3.6). Optional.
	CriticalSubjectMembers []string

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time

	// EventValidator, if set, vets every event passed to Emit before it
	// is signed — for example caep/interop.ValidateEvent, which enforces
	// the CAEP Interoperability Profile's subject formats and required
	// claims. Optional.
	EventValidator func(ssf.Subject, ssf.Event) error

	// AllowPushEndpoint, if set, vets every push endpoint_url a Receiver
	// supplies before the stream is created or changed. Push delivery
	// makes the Transmitter send requests to URLs Receivers choose, so a
	// deployment that must not reach internal hosts should restrict them
	// here. An error is reported to the Receiver as 400. Optional.
	AllowPushEndpoint func(rx Receiver, endpoint *url.URL) error

	// HTTPClient sends push deliveries. Defaults to NewPushClient(10s),
	// which refuses non-public addresses and redirects; supply a client to
	// push to Receivers on a private network.
	HTTPClient *http.Client

	// PushRetry controls how failed push deliveries are retried.
	PushRetry PushRetryPolicy

	// LongPollTimeout is how long a poll request that asks to wait
	// (returnImmediately false, RFC 8936 §2.5) waits for a SET before
	// returning none. Defaults to 20 seconds.
	LongPollTimeout time.Duration

	// Logger receives server-side failures (storage and authorizer
	// errors) that are reported to the Receiver only as 500. Defaults to
	// slog.Default().
	Logger *slog.Logger
}

// PushRetryPolicy controls retries of push deliveries that fail
// recoverably — a network error or any response but 2xx or an RFC 8935
// error. RFC 8935 §2 asks Transmitters to delay retransmission so as not
// to overwhelm the Receiver, and lets them cap attempts.
type PushRetryPolicy struct {
	// MinBackoff is the delay after the first failure; it doubles with
	// each further failure. Defaults to one second.
	MinBackoff time.Duration
	// MaxBackoff caps the delay. Defaults to five minutes.
	MaxBackoff time.Duration
	// MaxAttempts, if positive, is how many times a SET is tried before
	// it is dropped and logged. Zero retries indefinitely.
	MaxAttempts int
}

func (c *Config) validate() error {
	var errs []error
	if err := ssf.ValidateIssuer(c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if len(c.SigningKeys) == 0 {
		errs = append(errs, errors.New("SigningKeys is required"))
	}
	kids := map[string]bool{}
	for i, k := range c.SigningKeys {
		switch {
		case k.Signer == nil:
			errs = append(errs, fmt.Errorf("SigningKeys[%d]: Signer is required", i))
		case k.KeyID == "":
			errs = append(errs, fmt.Errorf("SigningKeys[%d]: KeyID is required", i))
		case kids[k.KeyID]:
			errs = append(errs, fmt.Errorf("SigningKeys[%d]: duplicate KeyID %q", i, k.KeyID))
		default:
			if err := jose.ValidateKeyForAlgorithm(k.Signer.Public(), k.Algorithm); err != nil {
				errs = append(errs, fmt.Errorf("SigningKeys[%d]: %w", i, err))
			}
		}
		kids[k.KeyID] = true
	}
	if len(c.EventsSupported) == 0 {
		errs = append(errs, errors.New("EventsSupported is required"))
	}
	if len(c.DeliveryMethods) == 0 {
		errs = append(errs, errors.New("DeliveryMethods is required"))
	}
	for _, m := range c.DeliveryMethods {
		if m != ssf.DeliveryPush && m != ssf.DeliveryPoll {
			errs = append(errs, fmt.Errorf("unsupported delivery method %q", m))
		}
	}
	if c.DefaultSubjects != ssf.DefaultSubjectsAll && c.DefaultSubjects != ssf.DefaultSubjectsNone {
		errs = append(errs, errors.New(`DefaultSubjects must be "ALL" or "NONE"`))
	}
	if c.Store == nil {
		errs = append(errs, errors.New("a Store is required"))
	}
	if c.Authorize == nil {
		errs = append(errs, errors.New("an Authorize function is required"))
	}
	if c.MinVerificationInterval < 0 || c.MinVerificationInterval%time.Second != 0 {
		errs = append(errs, errors.New("MinVerificationInterval must be a non-negative whole number of seconds"))
	}
	if c.PushRetry.MinBackoff < 0 || c.PushRetry.MaxBackoff < 0 || c.PushRetry.MaxAttempts < 0 {
		errs = append(errs, errors.New("PushRetry values must not be negative"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("transmitter: invalid config: %w", err)
	}
	if c.PushRetry.MinBackoff == 0 {
		c.PushRetry.MinBackoff = time.Second
	}
	if c.PushRetry.MaxBackoff == 0 {
		c.PushRetry.MaxBackoff = 5 * time.Minute
	}
	c.PushRetry.MaxBackoff = max(c.PushRetry.MaxBackoff, c.PushRetry.MinBackoff)
	return nil
}

func (c *Config) supportsDelivery(m ssf.DeliveryMethod) bool {
	return slices.Contains(c.DeliveryMethods, m)
}
