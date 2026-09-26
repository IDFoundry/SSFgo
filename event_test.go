package ssf

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type testEvent struct {
	N int `json:"n"`
}

func (testEvent) EventType() EventType { return "https://example.com/test" }

func (e testEvent) Validate() error {
	if e.N < 0 {
		return ErrInvalidEvent
	}
	return nil
}

type untypedEvent struct{}

func (untypedEvent) EventType() EventType { return "" }
func (untypedEvent) Validate() error      { return nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	want := []EventType{StreamUpdatedEventType, VerificationEventType}
	if got := r.Types(); !reflect.DeepEqual(got, want) {
		t.Fatalf("NewRegistry types = %v, want %v", got, want)
	}

	if err := Register[testEvent](r); err != nil {
		t.Fatal(err)
	}
	if err := Register[testEvent](r); err == nil {
		t.Error("registering a type twice succeeded")
	}
	if err := Register[untypedEvent](r); err == nil {
		t.Error("registering an event with an empty type succeeded")
	}
	if !r.Supports("https://example.com/test") {
		t.Error("Supports = false after Register")
	}

	e, err := r.Decode("https://example.com/test", json.RawMessage(` {"n":3,"ignored":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if e != (testEvent{N: 3}) {
		t.Errorf("Decode = %#v", e)
	}

	for name, payload := range map[string]string{
		"array":         `[]`,
		"null":          `null`,
		"string":        `"x"`,
		"wrong type":    `{"n":"three"}`,
		"invalid value": `{"n":-1}`,
		"truncated":     `{"n":`,
	} {
		if _, err := r.Decode("https://example.com/test", json.RawMessage(payload)); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: Decode error = %v, want ErrInvalidEvent", name, err)
		}
	}
	if _, err := r.Decode("https://example.com/other", json.RawMessage(`{}`)); !errors.Is(err, ErrUnsupportedEventType) {
		t.Errorf("unknown type: error = %v, want ErrUnsupportedEventType", err)
	}
}

func TestRegistryConcurrentUse(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _ = r.Decode(VerificationEventType, json.RawMessage(`{"state":"s"}`))
			_ = r.Types()
		})
	}
	wg.Go(func() { _ = Register[testEvent](r) })
	wg.Wait()
}

func TestSSFEvents(t *testing.T) {
	r := NewRegistry()
	e, err := r.Decode(StreamUpdatedEventType, json.RawMessage(`{"status":"paused","reason":"Internal error"}`))
	if err != nil {
		t.Fatal(err)
	}
	if e != (StreamUpdated{Status: StreamPaused, Reason: "Internal error"}) {
		t.Errorf("Decode = %#v", e)
	}
	for _, bad := range []string{`{}`, `{"status":"stopped"}`} {
		if _, err := r.Decode(StreamUpdatedEventType, json.RawMessage(bad)); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("stream-updated %s: error = %v", bad, err)
		}
	}

	stream := OpaqueSubject{ID: "f67e39a0a4d34d56b3aa1bc4cff0069f"}
	for _, ev := range []SubjectConstrainedEvent{Verification{}, StreamUpdated{Status: StreamEnabled}} {
		if err := ev.ValidateSubject(stream); err != nil {
			t.Errorf("%T with opaque subject: %v", ev, err)
		}
		if err := ev.ValidateSubject(EmailSubject{Email: "a@b.example"}); err == nil {
			t.Errorf("%T accepted a non-opaque subject", ev)
		}
	}

	// An unprompted verification has no state, and must encode without it.
	b, err := json.Marshal(Verification{})
	if err != nil || string(b) != `{}` {
		t.Errorf("Marshal(Verification{}) = %s, %v", b, err)
	}
}

func TestSETValidate(t *testing.T) {
	valid := SET{
		Issuer:   "https://tx.example.com",
		Audience: []string{"rx"},
		JWTID:    "1",
		IssuedAt: time.Unix(1, 0),
		Subject:  OpaqueSubject{ID: "stream-1"},
		Event:    Verification{State: "s"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wrongSubject := valid
	wrongSubject.Subject = EmailSubject{Email: "a@b.example"}
	if err := wrongSubject.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("verification with email subject: %v", err)
	}
}
