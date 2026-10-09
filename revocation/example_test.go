package revocation_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/revocation"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// A session-revoked event refuses the tokens of that session issued
// before it, and no others.
func ExampleRevoker_Middleware() {
	const idp = "https://idp.example.com" // its own Transmitter
	rev, err := revocation.New(revocation.Options{
		Store:     memstore.NewRevocationStore(),
		Issuers:   revocation.SameIssuer,
		Events:    revocation.RecommendedEvents(),
		Retention: 24 * time.Hour,
		Assurance: ssf.AssuranceDevelopment,
	})
	if err != nil {
		panic(err)
	}
	issued := time.Now().Add(-time.Minute)

	// What rx.Register(rev) would do as the SET arrives.
	err = rev.Handle(context.Background(), ssf.SET{
		Issuer:   idp,
		IssuedAt: time.Now(),
		Subject: ssf.ComplexSubject{
			User:    ssf.IssSubSubject{Issuer: idp, Subject: "alice"},
			Session: ssf.IssSubSubject{Issuer: idp, Subject: "session-1"},
		},
		Event: caep.SessionRevoked{},
	})
	if err != nil {
		panic(err)
	}

	api := rev.Middleware(func(r *http.Request) (revocation.Token, bool) {
		// The application's own token check would go here.
		return revocation.Token{Issuer: idp, Subject: "alice", SessionID: r.Header.Get("Session"), IssuedAt: issued}, true
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, session := range []string{"session-1", "session-2"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Session", session)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		fmt.Println(session, rec.Code)
	}
	// Output:
	// session-1 401
	// session-2 200
}
