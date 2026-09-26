// Package receiver is an embeddable SSF Receiver (OpenID Shared Signals
// Framework 1.0).
//
// A Receiver discovers a Transmitter, manages streams on it through the
// stream management API (SSF 1.0 §8), and takes delivery of Security Event
// Tokens by push (RFC 8935, through PushHandler) or poll (RFC 8936,
// through Poll or RunPoller). Every SET is verified — signature, issuer,
// audience, freshness, SSF §4 rules, event and subject validity — and
// de-duplicated before it reaches the application's handlers:
//
//	r, err := receiver.New(ctx, receiver.Config{...})
//	receiver.On(r, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error {
//		return sessions.Revoke(ctx, set.Subject)
//	})
//	stream, err := r.CreateStream(ctx, receiver.StreamRequest{...})
package receiver
