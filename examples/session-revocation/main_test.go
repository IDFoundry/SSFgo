package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExample(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"stream verified", "alice signed in", "ended local sessions [rp-session-1 rp-session-2]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}
