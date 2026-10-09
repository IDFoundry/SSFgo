// Package assurance applies ssf.AssuranceProduction's requirements, the
// same for every role.
package assurance

import (
	"crypto"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
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
// — and a URL whose host is Loopback.
func Check(level ssf.Assurance, scaled bool, deps Deps) []error {
	if !level.IsValid() {
		return []error{errors.New("the Assurance level must be ssf.AssuranceDevelopment or ssf.AssuranceProduction")}
	}
	if level != ssf.AssuranceProduction {
		return nil
	}
	var errs []error
	for _, s := range deps.Stores {
		if IsNil(s.Store) {
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

// Loopback reports whether raw is a URL whose host reaches this machine:
// "localhost" or a name under it, a loopback address, or the unspecified
// address, which connects to this machine too. IPv4 addresses are judged
// in every spelling a resolver accepts — "127.1", "2130706433",
// "0x7f.1" — not only dotted decimal.
func Loopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		var ok bool
		if ip, ok = legacyIPv4(host); !ok {
			return false
		}
	}
	ip = ip.WithZone("").Unmap()
	return ip.IsLoopback() || ip.IsUnspecified()
}

// legacyIPv4 parses s as inet_aton(3) does: one to four parts, each
// decimal, octal with a leading 0, or hexadecimal with 0x, the last
// filling the bytes that remain.
func legacyIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v uint64
	for i, p := range parts {
		if p == "" || strings.Contains(p, "_") {
			return netip.Addr{}, false
		}
		n, err := strconv.ParseUint(p, 0, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		bits := 8 * uint(4-i) // what the last part may fill
		if i < len(parts)-1 {
			bits = 8
		}
		if n >= 1<<bits {
			return netip.Addr{}, false
		}
		if i < len(parts)-1 {
			v = v<<8 | n
		} else {
			v = v<<bits | n
		}
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// IsNil reports whether v is nil, or an interface holding a nil pointer,
// map, slice, func or channel — a typed nil, whose methods would panic.
func IsNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// CustodyOf returns the custody declared for signer: declared, if it is
// not the zero value, or else what signer itself declares.
func CustodyOf(signer crypto.Signer, declared ssf.KeyCustody) ssf.KeyCustody {
	if declared != (ssf.KeyCustody{}) || IsNil(signer) {
		return declared
	}
	if a, ok := signer.(ssf.KeyCustodyAssurance); ok {
		return a.KeyCustody()
	}
	return ssf.KeyCustody{}
}
