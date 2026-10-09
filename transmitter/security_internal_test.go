package transmitter

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// Addresses that embed an IPv4 address must not smuggle an internal one
// past the push client.
func TestEmbeddedIPv4(t *testing.T) {
	for addr, want := range map[string]bool{
		"64:ff9b::7f00:1":      false, // NAT64 to 127.0.0.1
		"64:ff9b::a9fe:a9fe":   false, // NAT64 to 169.254.169.254
		"64:ff9b::a00:1":       false, // NAT64 to 10.0.0.1
		"64:ff9b::808:808":     true,  // NAT64 to 8.8.8.8 stays usable
		"::7f00:1":             false, // IPv4-compatible
		"2002:7f00:1::1":       false, // 6to4
		"2001:0:7f00:1::1":     false, // Teredo
		"::ffff:0:7f00:1":      false, // IPv4-translated
		"64:ff9b::ffff:7f00:1": false, // NAT64's range outside the well-known prefix
		"fec0::1":              false, // site-local
		"100::1":               false, // discard-only
		"2001:2::1":            false, // benchmarking
		"2606:4700::1111":      true,  // public IPv6 stays usable
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestValidHeaderValue(t *testing.T) {
	for v, want := range map[string]bool{
		"Bearer abc":              true,
		"Bearer a\tb":             true,
		"":                        true,
		"Bearer abc\r\nX-Evil: 1": false,
		"Bearer \x00":             false,
		"Bearer \x7f":             false,
	} {
		if got := validHeaderValue(v); got != want {
			t.Errorf("validHeaderValue(%q) = %v, want %v", v, got, want)
		}
	}
	if validHeaderValue(string(make([]byte, maxHeaderBytes+1))) {
		t.Error("an oversized header value was accepted")
	}
}

// ctxStore fails AckEvents once its context is done, as a database driver
// does.
type ctxStore struct{ storage.StreamStore }

func (s ctxStore) AckEvents(ctx context.Context, id string, jtis []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.StreamStore.AckEvents(ctx, id, jtis)
}

// A SET delivered as Run stops is still removed from its queue, not
// logged as an error and pushed again at the next start.
func TestDequeueOutlivesRun(t *testing.T) {
	var logged strings.Builder
	tx := &Transmitter{cfg: Config{Store: ctxStore{memstore.NewStreamStore()}}, log: slog.New(slog.NewTextHandler(&logged, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tx.dequeue(ctx, "s1", "jti-1") || logged.Len() > 0 {
		t.Errorf("dequeue after Run stopped asked for a retry, or logged %q", logged.String())
	}
}
