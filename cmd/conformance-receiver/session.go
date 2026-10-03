package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

const (
	// verificationRetry is how long a session waits for a verification
	// event before it requests another.
	verificationRetry = 15 * time.Second
	// cleanupTimeout bounds the final acknowledgement and stream deletion.
	cleanupTimeout = 30 * time.Second
)

// session is one Receiver run against one test module's emulated
// Transmitter.
type session struct {
	o        options
	client   *http.Client
	exposed  map[string]string
	moduleID string
	push     *pushRouter
	finished func() bool

	events       atomic.Int64
	verification atomic.Bool
}

func (s *session) run(ctx context.Context) error {
	issuer := s.exposed["ssf_issuer"]
	if issuer == "" {
		return errors.New("the module exposed no ssf_issuer")
	}
	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		return err
	}
	if err := risc.Register(registry); err != nil {
		return err
	}
	tokens, err := s.tokenSource()
	if err != nil {
		return err
	}
	cfg := receiver.Config{
		Issuer:      issuer,
		Audience:    s.o.audience,
		Registry:    registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256, ssf.ES256},
		TokenSource: tokens,
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  s.client,
	}
	if strings.Contains(s.o.plan, "caep") {
		// Hold the suite's emulated Transmitter to the CAEP Interop
		// Profile, as a CAEP Interop Receiver would.
		if err := interop.ApplyReceiver(&cfg); err != nil {
			return err
		}
	}
	rx, err := receiver.New(ctx, cfg)
	if err != nil {
		return err
	}
	for _, typ := range registry.Types() {
		rx.Handle(typ, func(_ context.Context, set ssf.SET) error {
			if _, ok := set.Event.(ssf.Verification); ok {
				s.verification.Store(true)
			} else {
				s.events.Add(1)
			}
			slog.Info("received", "module", s.moduleID, "event", set.Event.EventType(), "jti", set.JWTID)
			return nil
		})
	}

	req := receiver.StreamRequest{Description: "SSFgo conformance Receiver"}
	if s.o.delivery == "push" {
		auth := "Bearer " + random()
		s.push.set(s.moduleID, rx.PushHandler(receiver.PushOptions{AuthorizationHeader: auth}))
		defer s.push.set(s.moduleID, nil)
		req.Delivery = &ssf.Delivery{
			Method:              ssf.DeliveryPush,
			EndpointURL:         strings.TrimSuffix(s.o.pushBase, "/") + "/push/" + s.moduleID,
			AuthorizationHeader: auth,
		}
	} else {
		req.Delivery = &ssf.Delivery{Method: ssf.DeliveryPoll}
	}

	stream, err := rx.CreateStream(ctx, req)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	if _, err := rx.Stream(ctx, stream.StreamID); err != nil {
		return fmt.Errorf("read stream: %w", err)
	}
	if _, err := rx.Status(ctx, stream.StreamID); err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if _, err := rx.RequestVerification(ctx, stream.StreamID); err != nil {
		return fmt.Errorf("request verification: %w", err)
	}
	lastRequest := time.Now()

	// Take delivery until the module is satisfied, or events stop.
	lastCount, lastChange := int64(-1), time.Now()
	for ctx.Err() == nil && !s.finished() {
		if s.o.delivery == "poll" {
			if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
				slog.Warn("poll", "module", s.moduleID, "error", err)
			}
		}
		// The verification-wrong-state and -wrong-subject modules answer
		// the first request with an event the Receiver must reject, and
		// only a later request with one it accepts.
		if !s.verification.Load() && time.Since(lastRequest) > verificationRetry {
			if _, err := rx.RequestVerification(ctx, stream.StreamID); err != nil {
				slog.Warn("request verification again", "module", s.moduleID, "error", err)
			}
			lastRequest = time.Now()
		}
		if n := s.events.Load(); n != lastCount {
			lastCount, lastChange = n, time.Now()
		}
		if s.verification.Load() && time.Since(lastChange) > s.o.idle {
			break
		}
		time.Sleep(time.Second)
	}
	// Clean up even when the module ran out of time: most modules finish
	// only once the stream is deleted.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if s.o.delivery == "poll" {
		if err := rx.Acknowledge(ctx, stream); err != nil {
			slog.Warn("final acknowledgement", "module", s.moduleID, "error", err)
		}
	}
	if err := rx.DeleteStream(ctx, stream.StreamID); err != nil && !errors.Is(err, receiver.ErrNotFound) {
		return fmt.Errorf("delete stream: %w", err)
	}
	slog.Info("session done", "module", s.moduleID, "events", s.events.Load(), "verified", s.verification.Load())
	return nil
}

func (s *session) tokenSource() (receiver.TokenSource, error) {
	if s.o.auth == "static" {
		return receiver.StaticToken(s.exposed["ssf_tx_access_token"]), nil
	}
	cc := &receiver.ClientCredentials{
		TokenURL:     s.exposed["ssf_token_endpoint"],
		ClientID:     s.exposed["ssf_client_id"],
		ClientSecret: s.exposed["ssf_client_secret"],
		Scopes:       strings.Fields(s.exposed["ssf_client_scope"]),
		AuthMethod:   receiver.ClientAuthMethod(s.o.clientAuth),
		HTTPClient:   s.client,
	}
	switch cc.AuthMethod {
	case receiver.ClientSecretBasic, receiver.ClientSecretPost, receiver.ClientSecretJWT:
	case receiver.PrivateKeyJWT:
		cc.SigningKey, cc.SigningAlgorithm, cc.KeyID = s.o.assertionKey, ssf.PS256, assertionKeyID
	default:
		return nil, fmt.Errorf("unsupported -client-auth %q", s.o.clientAuth)
	}
	return cc, nil
}
