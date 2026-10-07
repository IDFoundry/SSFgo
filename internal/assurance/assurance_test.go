package assurance

import (
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

type declares storage.Capabilities

func (d declares) Capabilities() storage.Capabilities { return storage.Capabilities(d) }

func TestCheck(t *testing.T) {
	memory := declares{}
	durable := declares{Durable: true}
	shared := declares{Durable: true, CrossInstanceConsistent: true}
	for name, c := range map[string]struct {
		level  ssf.Assurance
		scaled bool
		store  any
		url    string
		want   string // "" for no error
	}{
		"no level":                  {"", false, shared, "", "Assurance level must be"},
		"development, memory":       {ssf.AssuranceDevelopment, true, memory, "https://localhost", ""},
		"production, memory":        {ssf.AssuranceProduction, false, memory, "", "S must declare itself durable"},
		"production, undeclared":    {ssf.AssuranceProduction, false, struct{}{}, "", "S must declare itself durable"},
		"production, durable":       {ssf.AssuranceProduction, false, durable, "https://tx.example", ""},
		"scaled, durable only":      {ssf.AssuranceProduction, true, durable, "", "S must declare itself consistent across instances"},
		"scaled, shared":            {ssf.AssuranceProduction, true, shared, "", ""},
		"production, localhost":     {ssf.AssuranceProduction, false, shared, "https://localhost:8443/ssf", "U must not be a loopback host"},
		"production, loopback IP":   {ssf.AssuranceProduction, false, shared, "https://127.0.0.1", "U must not be a loopback host"},
		"production, loopback v6":   {ssf.AssuranceProduction, false, shared, "https://[::1]/", "U must not be a loopback host"},
		"production, .localhost":    {ssf.AssuranceProduction, false, shared, "https://tx.localhost", "U must not be a loopback host"},
		"production, missing store": {ssf.AssuranceProduction, false, nil, "", ""},
	} {
		errs := Check(c.level, c.scaled, []Store{{Field: "S", Store: c.store}}, []URL{{Field: "U", Value: c.url}})
		var got []string
		for _, err := range errs {
			got = append(got, err.Error())
		}
		joined := strings.Join(got, "; ")
		if (c.want == "") != (len(errs) == 0) || !strings.Contains(joined, c.want) {
			t.Errorf("%s: %q, want %q", name, joined, c.want)
		}
	}
}
