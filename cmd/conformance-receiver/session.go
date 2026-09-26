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
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage/memstore"
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
	rx, err := receiver.New(ctx, receiver.Config{
		Issuer:      issuer,
		Audience:    s.o.audience,
		Registry:    registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256, ssf.ES256},
		TokenSource: tokens,
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  s.client,
	})
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

	// Take delivery until the module is satisfied, or events stop.
	lastCount, lastChange := int64(-1), time.Now()
	for ctx.Err() == nil && !s.finished() {
		if s.o.delivery == "poll" {
			if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
				slog.Warn("poll", "module", s.moduleID, "error", err)
			}
		}
		if n := s.events.Load(); n != lastCount {
			lastCount, lastChange = n, time.Now()
		}
		if s.verification.Load() && time.Since(lastChange) > s.o.idle {
			break
		}
		time.Sleep(time.Second)
	}
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
	method := receiver.ClientAuthMethod(s.o.clientAuth)
	if method != receiver.ClientSecretBasic && method != receiver.ClientSecretPost {
		return nil, fmt.Errorf("unsupported -client-auth %q", s.o.clientAuth)
	}
	return &receiver.ClientCredentials{
		TokenURL:     s.exposed["ssf_token_endpoint"],
		ClientID:     s.exposed["ssf_client_id"],
		ClientSecret: s.exposed["ssf_client_secret"],
		Scopes:       strings.Fields(s.exposed["ssf_client_scope"]),
		AuthMethod:   method,
		HTTPClient:   s.client,
	}, nil
}
