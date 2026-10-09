package receiver_test

import (
	"context"
	"log/slog"
	"os"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// A Receiver for development: in-memory replay protection, and an access
// token from the client credentials grant.
func ExampleNew() {
	ctx := context.Background()
	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		panic(err)
	}
	rx, err := receiver.New(ctx, receiver.Config{
		Issuer:     "https://idp.example.com",
		Audience:   "https://rp.example.com",
		Registry:   registry,
		Algorithms: receiver.RecommendedAlgorithms(),
		TokenSource: &receiver.ClientCredentials{
			TokenURL:     "https://idp.example.com/oauth2/token",
			ClientID:     "rp",
			ClientSecret: ssf.NewSecret(os.Getenv("SSF_CLIENT_SECRET")),
			AuthMethod:   receiver.ClientSecretBasic,
		},
		ReplayStore: memstore.NewReplayStore(),
		Assurance:   ssf.AssuranceDevelopment,
		Limits:      receiver.RecommendedLimits(),
	})
	if err != nil {
		panic(err) // every problem with the configuration, or the Transmitter unreachable
	}
	_ = rx
}

// Handlers are typed by event. An error has the Transmitter deliver the
// SET again.
func ExampleOn() {
	var rx *receiver.Receiver // from receiver.New
	receiver.On(rx, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error {
		slog.InfoContext(ctx, "session revoked", "subject", set.Subject.Format())
		return nil
	})
}
