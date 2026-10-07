// Package assurance applies ssf.AssuranceProduction's requirements, the
// same for every role.
package assurance

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// Store is a store a role depends on, named by its config field.
type Store struct {
	Field string
	Store any
}

// URL is a URL a role is configured with, named by its config field.
type URL struct {
	Field, Value string
}

// Key is a private key a role uses, named by its config field, with the
// custody declared for it (ssf.CustodyOf).
type Key struct {
	Field   string
	Custody ssf.KeyCustody
}

// Deps is what a role depends on that production assurance checks.
type Deps struct {
	Stores []Store
	URLs   []URL
	Keys   []Key
}

// Check returns the problems with a role's configuration under level: an
// invalid level; and under production, a store or key that is not
// declared durable — or, when scaled is set, consistent across instances
// — and a URL whose host is a loopback address or "localhost".
func Check(level ssf.Assurance, scaled bool, deps Deps) []error {
	if !level.IsValid() {
		return []error{errors.New("the Assurance level must be ssf.AssuranceDevelopment or ssf.AssuranceProduction")}
	}
	if level != ssf.AssuranceProduction {
		return nil
	}
	var errs []error
	for _, s := range deps.Stores {
		if s.Store == nil {
			continue // reported as missing by the role's own checks
		}
		c := storage.CapabilitiesOf(s.Store)
		if !c.Durable {
			errs = append(errs, fmt.Errorf("under AssuranceProduction, %s must declare itself durable (an in-memory store loses everything on restart)", s.Field))
		}
		if scaled && !c.CrossInstanceConsistent {
			errs = append(errs, fmt.Errorf("with HorizontallyScaled under AssuranceProduction, %s must declare itself consistent across instances", s.Field))
		}
	}
	for _, k := range deps.Keys {
		if !k.Custody.Durable {
			errs = append(errs, fmt.Errorf("under AssuranceProduction, %s must be declared durable (ssf.KeyCustody): a key made at each start strands what was signed before a restart", k.Field))
		}
		if scaled && !k.Custody.CrossInstanceConsistent {
			errs = append(errs, fmt.Errorf("with HorizontallyScaled under AssuranceProduction, %s must be declared shared by every instance (ssf.KeyCustody)", k.Field))
		}
	}
	for _, u := range deps.URLs {
		if u.Value != "" && Loopback(u.Value) {
			errs = append(errs, fmt.Errorf("under AssuranceProduction, %s must not be a loopback host", u.Field))
		}
	}
	return errs
}

// Loopback reports whether raw is a URL whose host is a loopback
// address or "localhost".
func Loopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CustodyOf returns the custody declared for signer: declared, if it is
// not the zero value, or else what signer itself declares.
func CustodyOf(signer crypto.Signer, declared ssf.KeyCustody) ssf.KeyCustody {
	if declared != (ssf.KeyCustody{}) {
		return declared
	}
	if a, ok := signer.(ssf.KeyCustodyAssurance); ok {
		return a.KeyCustody()
	}
	return ssf.KeyCustody{}
}
