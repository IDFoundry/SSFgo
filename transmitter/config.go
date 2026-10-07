package transmitter

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/assurance"
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

	// Assurance is the deployment the Transmitter is for. Required.
	// Under ssf.AssuranceProduction, Store must declare itself durable
	// (storage.Capabilities) and Issuer must not be a loopback host.
	Assurance ssf.Assurance

	// HorizontallyScaled declares that several Transmitter instances share
	// Store. Under ssf.AssuranceProduction, Store must then declare itself
	// consistent across instances.
	HorizontallyScaled bool

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
	// push to Receivers on a private network. A client supplied for other
	// reasons keeps the address check only if its dialer uses
	// PublicAddressControl.
	HTTPClient *http.Client

	// PushRetry controls how failed push deliveries are retried.
	// Required when DeliveryMethods includes push: RecommendedPushRetry
	// is the usual choice.
	PushRetry PushRetryPolicy

	// Limits bound what one Receiver can make the Transmitter store or
	// wait for. Required: RecommendedLimits is the usual choice.
	Limits Limits

	// Inactivity, if its Timeout is set, advertises inactivity_timeout on
	// every stream and acts on streams whose Receiver has gone quiet
	// (SSF 1.0 §8.1.1). Optional.
	Inactivity InactivityPolicy

	// VerifyNewStreams sends a Transmitter-initiated verification event,
	// without state, on every stream as soon as it is created (SSF 1.0
	// §8.1.4), so the Receiver learns at once whether delivery works.
	VerifyNewStreams bool

	// PermitEvent decides whether the Receiver that owns a stream may
	// receive a given event about a given subject. Emit consults it for
	// every stream the event would otherwise be queued on. SSF 1.0 §9.2
	// asks Transmitters to check they are permitted to share an event
	// before transmitting it. Subject rules cannot stand in for it: with
	// default_subjects "ALL" any Receiver gets every event simply by
	// creating a stream, with "NONE" by adding the subject, and one
	// complex subject can match many (§8.1.3.1). Required; PermitAll
	// permits every event, for a Transmitter whose every Receiver may see
	// events about every subject.
	PermitEvent func(ctx context.Context, receiverID string, subject ssf.Subject, event ssf.Event) bool

	// Logger receives server-side failures (storage and authorizer
	// errors) that are reported to the Receiver only as 500. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// Hooks observe the Transmitter, to feed metrics or traces. Optional.
	Hooks Hooks
}

// PermitAll is a PermitEvent that permits every event: for a Transmitter
// whose every Receiver may see events about every subject, such as a
// single-tenant deployment.
func PermitAll(context.Context, string, ssf.Subject, ssf.Event) bool { return true }

// Limits bound the state an authenticated Receiver can create and how
// long it can hold a request open. Each must be positive: there is
// deliberately no "unlimited" and no implicit default, and
// RecommendedLimits gives starting values.
type Limits struct {
	// StreamsPerReceiver caps how many streams one Receiver may own when
	// MultipleStreamsPerReceiver is set.
	StreamsPerReceiver int
	// SubjectRulesPerStream caps Add and Remove Subject rules per stream.
	SubjectRulesPerStream int
	// QueuedSETsPerStream caps the SETs waiting on one stream. Once a
	// Receiver stops collecting, further SETs for that stream are dropped
	// and logged rather than held without bound.
	QueuedSETsPerStream int
	// LongPollTimeout is how long a poll request that asks to wait
	// (returnImmediately false, RFC 8936 §2.5) waits for a SET before
	// returning none.
	LongPollTimeout time.Duration
}

// RecommendedLimits returns starting values for Limits. None is a
// specification requirement; each is this package's operational choice:
//
//   - StreamsPerReceiver 10: room for a Receiver's environments or
//     tenants without one Receiver filling the store.
//   - SubjectRulesPerStream 10,000 and QueuedSETsPerStream 10,000: ample
//     for a Receiver that collects its SETs, bounded for one that stops.
//   - LongPollTimeout 20 seconds: under the idle timeouts of common
//     proxies and load balancers, so a waiting poll is answered before
//     something in between closes it.
func RecommendedLimits() Limits {
	return Limits{StreamsPerReceiver: 10, SubjectRulesPerStream: 10_000, QueuedSETsPerStream: 10_000, LongPollTimeout: 20 * time.Second}
}

// RecommendedPushRetry returns a starting PushRetryPolicy: retries one
// second after the first failure, doubling to at most five minutes, with
// no limit on attempts — a SET is dropped only when the Receiver rejects
// it, or keeps rejecting it with an error that may clear (RFC 8935 §2:
// Transmitters delay retransmission and may cap attempts).
func RecommendedPushRetry() PushRetryPolicy {
	return PushRetryPolicy{MinBackoff: time.Second, MaxBackoff: 5 * time.Minute}
}

// InactivityAction is what the Transmitter does to a stream whose
// inactivity timeout has passed (SSF 1.0 §8.1.1).
type InactivityAction string

const (
	// InactivityPause pauses the stream: SETs are held, and the Receiver
	// can re-enable it.
	InactivityPause InactivityAction = "pause"
	// InactivityDisable disables the stream: queued SETs are discarded
	// and no more are held. The Receiver can re-enable it.
	InactivityDisable InactivityAction = "disable"
	// InactivityDelete deletes the stream.
	InactivityDelete InactivityAction = "delete"
)

// InactivityPolicy configures inactivity_timeout (SSF 1.0 §8.1.1).
//
// Eligible Receiver activity, which restarts the timeout, is any stream
// management request that references the stream — reading it or its
// status, updating it, subject changes, verification requests — and, for
// poll streams, polling. Pausing or disabling a stream sends the
// stream-updated event SSF requires; unlike SetStreamStatus, it does not
// stop the Receiver re-enabling the stream. Timeouts are enforced by Run,
// or by calling ExpireInactiveStreams.
type InactivityPolicy struct {
	// Timeout is advertised in whole seconds. Zero turns the feature off.
	Timeout time.Duration
	// Action is required when Timeout is set.
	Action InactivityAction
}

// PushRetryPolicy controls retries of push deliveries that fail
// recoverably — a network error, any response but 2xx or an RFC 8935
// error, or an RFC 8935 error that may clear on its own (invalid_key,
// authentication_failed, access_denied), which is retried at most eight
// times. RFC 8935 §2 asks Transmitters to delay retransmission so as not
// to overwhelm the Receiver, and lets them cap attempts.
type PushRetryPolicy struct {
	// MinBackoff is the delay after the first failure; it doubles with
	// each further failure. Positive.
	MinBackoff time.Duration
	// MaxBackoff caps the delay. At least MinBackoff.
	MaxBackoff time.Duration
	// MaxAttempts, if positive, is how many times a SET is tried before
	// it is dropped and logged. Zero retries indefinitely.
	MaxAttempts int
}

func (c *Config) validate() error {
	errs := c.requiredErrors()
	errs = append(errs, assurance.Check(c.Assurance, c.HorizontallyScaled,
		[]assurance.Store{{Field: "Store", Store: c.Store}},
		[]assurance.URL{{Field: "Issuer", Value: c.Issuer}})...)
	errs = append(errs, c.signingKeyErrors()...)
	errs = append(errs, c.tuningErrors()...)
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("transmitter: invalid config: %w", err)
	}
	return nil
}

// signingKeyErrors checks SigningKeys: at least one, each with a Signer
// suited to its algorithm and a unique KeyID.
func (c *Config) signingKeyErrors() []error {
	var errs []error
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
	return errs
}

// requiredErrors checks the settings every Transmitter must have.
func (c *Config) requiredErrors() []error {
	var errs []error
	if err := ssf.ValidateIssuer(c.Issuer); err != nil {
		errs = append(errs, err)
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
	if c.PermitEvent == nil {
		errs = append(errs, errors.New("a PermitEvent function is required; PermitAll permits every event"))
	}
	return errs
}

// tuningErrors checks the optional durations and limits.
func (c *Config) tuningErrors() []error {
	var errs []error
	if c.MinVerificationInterval < 0 || c.MinVerificationInterval%time.Second != 0 {
		errs = append(errs, errors.New("MinVerificationInterval must be a non-negative whole number of seconds"))
	}
	if c.supportsDelivery(ssf.DeliveryPush) && (c.PushRetry.MinBackoff <= 0 || c.PushRetry.MaxBackoff < c.PushRetry.MinBackoff) {
		errs = append(errs, errors.New("PushRetry.MinBackoff must be positive and PushRetry.MaxBackoff at least as long (RecommendedPushRetry gives starting values)"))
	}
	if c.PushRetry.MaxAttempts < 0 {
		errs = append(errs, errors.New("PushRetry.MaxAttempts must not be negative"))
	}
	l := c.Limits
	if l.StreamsPerReceiver <= 0 || l.SubjectRulesPerStream <= 0 || l.QueuedSETsPerStream <= 0 || l.LongPollTimeout <= 0 {
		errs = append(errs, errors.New("Limits.StreamsPerReceiver, SubjectRulesPerStream, QueuedSETsPerStream and LongPollTimeout must be positive (RecommendedLimits gives starting values)"))
	}
	if c.Inactivity.Timeout < 0 || c.Inactivity.Timeout%time.Second != 0 {
		errs = append(errs, errors.New("Inactivity.Timeout must be a non-negative whole number of seconds"))
	}
	if c.Inactivity.Timeout > 0 {
		switch c.Inactivity.Action {
		case InactivityPause, InactivityDisable, InactivityDelete:
		default:
			errs = append(errs, errors.New(`Inactivity.Action must be "pause", "disable" or "delete"`))
		}
	}
	return errs
}

func (c *Config) supportsDelivery(m ssf.DeliveryMethod) bool {
	return slices.Contains(c.DeliveryMethods, m)
}
