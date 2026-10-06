package sqlstore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/sqlstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

// Benchmarks for sqlstore's operations on the Transmitter's hot paths, on
// SQLite and, with SSFGO_TEST_POSTGRES set, PostgreSQL. Run with
//
//	go test -run '^$' -bench . ./...
func BenchmarkStreamStore(b *testing.B) {
	for _, d := range dialects {
		b.Run(d.name, func(b *testing.B) {
			db := d.open(b)
			st, err := sqlstore.NewStreamStore(db, d.dialect)
			if err != nil {
				b.Fatal(err)
			}
			s := storage.Stream{ID: "s1", ReceiverID: "r1", Status: ssf.StreamEnabled, Audience: []string{"https://rx.example"}}
			if err := st.CreateStream(ctx, s, storage.CreateOptions{}); err != nil {
				b.Fatal(err)
			}

			b.Run("Enqueue", func(b *testing.B) {
				i := 0
				for b.Loop() {
					i++
					if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: fmt.Sprint("e", i), SET: "a.b.c"}, 0); err != nil {
						b.Fatal(err)
					}
				}
			})
			if err := st.PurgeEvents(ctx, "s1"); err != nil {
				b.Fatal(err)
			}
			for i := range 10 {
				if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: fmt.Sprint("p", i), SET: "a.b.c"}, 0); err != nil {
					b.Fatal(err)
				}
			}
			b.Run("PendingEvents10", func(b *testing.B) {
				for b.Loop() {
					if q, err := st.PendingEvents(ctx, "s1", 10, false); err != nil || len(q) != 10 {
						b.Fatal(len(q), err)
					}
				}
			})
			b.Run("UpdateStream", func(b *testing.B) {
				for b.Loop() {
					if _, err := st.UpdateStream(ctx, "s1", func(s *storage.Stream) error {
						s.LastActivity = time.Now()
						return nil
					}); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("AllStreams100", func(b *testing.B) {
				for i := range 99 {
					s := storage.Stream{ID: fmt.Sprint("x", i), ReceiverID: "r2", Status: ssf.StreamEnabled}
					if err := st.CreateStream(ctx, s, storage.CreateOptions{}); err != nil {
						b.Fatal(err)
					}
				}
				for b.Loop() {
					if all, err := st.AllStreams(ctx); err != nil || len(all) != 100 {
						b.Fatal(len(all), err)
					}
				}
			})

			replay, err := sqlstore.NewReplayStore(db, d.dialect)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("MarkSET", func(b *testing.B) {
				until := time.Now().Add(time.Hour)
				i := 0
				for b.Loop() {
					i++
					if fresh, err := replay.MarkSET(ctx, "https://iss", fmt.Sprint(i), until); err != nil || !fresh {
						b.Fatal(fresh, err)
					}
				}
			})
		})
	}
}

// BenchmarkEmit measures Transmitter.Emit routing one event to ten poll
// streams stored in sqlstore; compare transmitter's BenchmarkEmit on
// memstore to see what the database adds to signing.
func BenchmarkEmit(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	for _, d := range dialects {
		b.Run(d.name, func(b *testing.B) {
			store, err := sqlstore.NewStreamStore(d.open(b), d.dialect)
			if err != nil {
				b.Fatal(err)
			}
			tx, err := transmitter.New(transmitter.Config{
				Limits:          transmitter.RecommendedLimits(),
				PushRetry:       transmitter.RecommendedPushRetry(),
				PermitEvent:     transmitter.PermitAll,
				Issuer:          "https://tx.example",
				SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "k1"}},
				EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
				DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
				DefaultSubjects: ssf.DefaultSubjectsAll,
				Store:           store,
				Authorize: func(ctx context.Context, _ string) (transmitter.Receiver, error) {
					return transmitter.Receiver{}, transmitter.ErrInvalidToken
				},
				Logger: slog.New(slog.DiscardHandler),
			})
			if err != nil {
				b.Fatal(err)
			}
			for i := range 10 {
				s := storage.Stream{
					ID: fmt.Sprint("s", i), ReceiverID: fmt.Sprint("r", i), Status: ssf.StreamEnabled,
					Audience:        []string{"https://rx.example"},
					Delivery:        ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: "https://tx.example/poll"},
					EventsRequested: []ssf.EventType{caep.SessionRevokedEventType},
					EventsDelivered: []ssf.EventType{caep.SessionRevokedEventType},
				}
				if err := store.CreateStream(ctx, s, storage.CreateOptions{}); err != nil {
					b.Fatal(err)
				}
			}
			event := caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "bench"}}}
			subject := ssf.EmailSubject{Email: "alice@example.com"}
			for b.Loop() {
				if err := tx.Emit(ctx, subject, event); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(10*b.N)/b.Elapsed().Seconds(), "SETs/s")
		})
	}
}
