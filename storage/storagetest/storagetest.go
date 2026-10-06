// Package storagetest is a contract test suite for implementations of
// SSFgo's storage interfaces. Run it from the implementation's own tests:
//
//	func TestContract(t *testing.T) {
//		storagetest.StreamStore(t, func(t *testing.T) storage.StreamStore { return mystore.New(...) })
//	}
package storagetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// StreamStore runs the storage.StreamStore contract against stores made by
// newStore. Each subtest gets a fresh, empty store.
func StreamStore(t *testing.T, newStore func(t *testing.T) storage.StreamStore) {
	tests := []struct {
		name string
		run  func(*testing.T, storage.StreamStore)
	}{
		{"CreateAndGet", testCreateAndGet},
		{"CreateDuplicateID", testCreateDuplicateID},
		{"MaxStreamsPerReceiver", testSingleStreamPerReceiver},
		{"Limits", testLimits},
		{"NotFound", testNotFound},
		{"StreamsForReceiver", testStreamsForReceiver},
		{"AllStreams", testAllStreams},
		{"Update", testUpdate},
		{"UpdateErrorStoresNothing", testUpdateErrorStoresNothing},
		{"ReturnedValuesAreCopies", testReturnedValuesAreCopies},
		{"Delete", testDelete},
		{"SubjectRules", testSubjectRules},
		{"Queue", testQueue},
		{"AckAndPurge", testAckAndPurge},
		{"ConcurrentUpdates", testConcurrentUpdates},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

var ctx = context.Background()

func sampleStream(id, receiver string) storage.Stream {
	return storage.Stream{
		ID:              id,
		ReceiverID:      receiver,
		Audience:        []string{"https://rx.example.com/" + receiver},
		Delivery:        ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: "https://rx.example.com/events", AuthorizationHeader: ssf.NewSecret("Bearer x")},
		EventsRequested: []ssf.EventType{"https://example.com/a", "https://example.com/b"},
		EventsDelivered: []ssf.EventType{"https://example.com/a"},
		Description:     "sample",
		Status:          ssf.StreamEnabled,
		CreatedAt:       time.Unix(1700000000, 0).UTC(),
	}
}

func mustCreate(t *testing.T, st storage.StreamStore, s storage.Stream) {
	t.Helper()
	if err := st.CreateStream(ctx, s, storage.CreateOptions{}); err != nil {
		t.Fatalf("CreateStream(%s): %v", s.ID, err)
	}
}

func testCreateAndGet(t *testing.T, st storage.StreamStore) {
	want := sampleStream("s1", "r1")
	mustCreate(t, st, want)
	got, err := st.Stream(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !streamsEqual(got, want) {
		t.Errorf("Stream = %+v, want %+v", got, want)
	}
}

func testCreateDuplicateID(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	if err := st.CreateStream(ctx, sampleStream("s1", "r2"), storage.CreateOptions{}); !errors.Is(err, storage.ErrExists) {
		t.Errorf("CreateStream(duplicate ID) = %v, want ErrExists", err)
	}
}

func testSingleStreamPerReceiver(t *testing.T, st storage.StreamStore) {
	two := storage.CreateOptions{MaxStreamsPerReceiver: 2}
	for _, id := range []string{"s1", "s2"} {
		if err := st.CreateStream(ctx, sampleStream(id, "r1"), two); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateStream(ctx, sampleStream("s3", "r1"), two); !errors.Is(err, storage.ErrTooManyStreams) {
		t.Errorf("third stream for r1 = %v, want ErrTooManyStreams", err)
	}
	if err := st.CreateStream(ctx, sampleStream("s4", "r2"), two); err != nil {
		t.Errorf("first stream for r2: %v", err)
	}
	if err := st.CreateStream(ctx, sampleStream("s5", "r1"), storage.CreateOptions{}); err != nil {
		t.Errorf("without a limit a receiver may own any number of streams: %v", err)
	}
	for _, id := range []string{"s1", "s5"} {
		if err := st.DeleteStream(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateStream(ctx, sampleStream("s6", "r1"), two); err != nil {
		t.Errorf("after deleting below the limit: %v", err)
	}
}

func testLimits(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	for i := range 2 {
		rule := storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: fmt.Sprint(i)}, Included: true}
		if err := st.SetSubjectRule(ctx, "s1", rule, 2); err != nil {
			t.Fatal(err)
		}
	}
	extra := storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "extra"}, Included: true}
	if err := st.SetSubjectRule(ctx, "s1", extra, 2); !errors.Is(err, storage.ErrTooManySubjectRules) {
		t.Errorf("rule beyond the limit = %v, want ErrTooManySubjectRules", err)
	}
	replace := storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "0"}, Included: false}
	if err := st.SetSubjectRule(ctx, "s1", replace, 2); err != nil {
		t.Errorf("replacing a rule at the limit: %v", err)
	}

	for i := range 2 {
		if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: fmt.Sprint(i), SET: "x"}, 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: "extra", SET: "x"}, 2); !errors.Is(err, storage.ErrQueueFull) {
		t.Errorf("enqueue beyond the limit = %v, want ErrQueueFull", err)
	}
	if err := st.AckEvents(ctx, "s1", []string{"0"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: "after-ack", SET: "x"}, 2); err != nil {
		t.Errorf("enqueue after an acknowledgement frees space: %v", err)
	}
}

func testNotFound(t *testing.T, st storage.StreamStore) {
	calls := map[string]error{}
	_, calls["Stream"] = st.Stream(ctx, "nope")
	_, calls["UpdateStream"] = st.UpdateStream(ctx, "nope", func(*storage.Stream) error { return nil })
	calls["DeleteStream"] = st.DeleteStream(ctx, "nope")
	calls["SetSubjectRule"] = st.SetSubjectRule(ctx, "nope", storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "x"}}, 0)
	_, calls["SubjectRules"] = st.SubjectRules(ctx, "nope")
	calls["Enqueue"] = st.Enqueue(ctx, "nope", storage.QueuedEvent{JTI: "1", SET: "x"}, 0)
	_, calls["PendingEvents"] = st.PendingEvents(ctx, "nope", 0, false)
	calls["AckEvents"] = st.AckEvents(ctx, "nope", []string{"1"})
	calls["PurgeEvents"] = st.PurgeEvents(ctx, "nope")
	for name, err := range calls {
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("%s(unknown stream) = %v, want ErrNotFound", name, err)
		}
	}
}

func testStreamsForReceiver(t *testing.T, st storage.StreamStore) {
	got, err := st.StreamsForReceiver(ctx, "r1")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("StreamsForReceiver(no streams) = %#v, %v; want an empty non-nil slice", got, err)
	}
	for i, id := range []string{"c", "a", "b"} {
		s := sampleStream(id, "r1")
		s.CreatedAt = s.CreatedAt.Add(time.Duration(i) * time.Second)
		mustCreate(t, st, s)
	}
	mustCreate(t, st, sampleStream("other", "r2"))
	got, err = st.StreamsForReceiver(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	if !reflect.DeepEqual(ids, []string{"c", "a", "b"}) {
		t.Errorf("StreamsForReceiver = %v, want [c a b] (oldest first)", ids)
	}
}

func testAllStreams(t *testing.T, st storage.StreamStore) {
	if all, err := st.AllStreams(ctx); err != nil || len(all) != 0 {
		t.Fatalf("AllStreams(empty) = %v, %v", all, err)
	}
	mustCreate(t, st, sampleStream("b", "r1"))
	mustCreate(t, st, sampleStream("a", "r2"))
	all, err := st.AllStreams(ctx)
	if err != nil || len(all) != 2 || all[0].ID != "b" || all[1].ID != "a" {
		t.Errorf("AllStreams = %+v, %v; want [b a], oldest first", all, err)
	}
}

func testUpdate(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	updated, err := st.UpdateStream(ctx, "s1", func(s *storage.Stream) error {
		s.Status = ssf.StreamPaused
		s.StatusReason = "maintenance"
		s.Description = ""
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.Stream(ctx, "s1")
	if !streamsEqual(got, updated) || got.Status != ssf.StreamPaused || got.Description != "" {
		t.Errorf("after update: stored %+v, returned %+v", got, updated)
	}
}

func testUpdateErrorStoresNothing(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	sentinel := fmt.Errorf("rejected")
	_, err := st.UpdateStream(ctx, "s1", func(s *storage.Stream) error {
		s.Description = "changed"
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("UpdateStream error = %v, want the update's own error", err)
	}
	if got, _ := st.Stream(ctx, "s1"); got.Description != "sample" {
		t.Errorf("a failed update was stored: %q", got.Description)
	}
}

func testReturnedValuesAreCopies(t *testing.T, st storage.StreamStore) {
	s := sampleStream("s1", "r1")
	mustCreate(t, st, s)
	s.Audience[0] = "mutated-after-create"

	got, _ := st.Stream(ctx, "s1")
	got.Audience[0] = "mutated-after-get"
	got.EventsDelivered[0] = "mutated"

	again, _ := st.Stream(ctx, "s1")
	if again.Audience[0] != "https://rx.example.com/r1" || again.EventsDelivered[0] != "https://example.com/a" {
		t.Errorf("stored state changed through a returned or passed-in value: %+v", again)
	}
}

func testDelete(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	if err := st.SetSubjectRule(ctx, "s1", storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "x"}, Included: true}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: "1", SET: "a.b.c"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Stream(ctx, "s1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Stream after delete = %v", err)
	}
	// Recreating the ID must not resurrect the old subjects or queue.
	mustCreate(t, st, sampleStream("s1", "r1"))
	if rules, _ := st.SubjectRules(ctx, "s1"); len(rules) != 0 {
		t.Errorf("subject rules survived delete: %v", rules)
	}
	if q, _ := st.PendingEvents(ctx, "s1", 0, false); len(q) != 0 {
		t.Errorf("queued events survived delete: %v", q)
	}
}

func testSubjectRules(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	a := ssf.EmailSubject{Email: "a@example.com"}
	b := ssf.ComplexSubject{User: ssf.OpaqueSubject{ID: "u"}, Tenant: ssf.OpaqueSubject{ID: "t"}}
	bReordered := ssf.ComplexSubject{Tenant: ssf.OpaqueSubject{ID: "t"}, User: ssf.OpaqueSubject{ID: "u"}}
	set := func(r storage.SubjectRule) {
		t.Helper()
		if err := st.SetSubjectRule(ctx, "s1", r, 0); err != nil {
			t.Fatal(err)
		}
	}
	want := func(step string, first, second storage.SubjectRule) {
		t.Helper()
		rules, err := st.SubjectRules(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 2 {
			t.Fatalf("%s: SubjectRules = %v, want one rule per distinct subject", step, rules)
		}
		for i, w := range []storage.SubjectRule{first, second} {
			if !ssf.SubjectsEqual(rules[i].Subject, w.Subject) || rules[i].Included != w.Included {
				t.Errorf("%s: rule %d = %+v, want %+v", step, i, rules[i], w)
			}
		}
	}
	set(storage.SubjectRule{Subject: a, Included: true})
	set(storage.SubjectRule{Subject: b, Included: true})
	// Replacing a rule makes it the newest.
	set(storage.SubjectRule{Subject: a, Included: false})
	want("after replacing a", storage.SubjectRule{Subject: b, Included: true}, storage.SubjectRule{Subject: a, Included: false})
	// Equal subjects are matched by ssf.SubjectsEqual, not encoding.
	set(storage.SubjectRule{Subject: bReordered, Included: false})
	want("after replacing b", storage.SubjectRule{Subject: a, Included: false}, storage.SubjectRule{Subject: b, Included: false})
}

func testQueue(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	mustCreate(t, st, sampleStream("s2", "r1"))
	q, err := st.PendingEvents(ctx, "s1", 0, false)
	if err != nil || len(q) != 0 {
		t.Fatalf("empty queue = %v, %v", q, err)
	}
	for i := range 3 {
		e := storage.QueuedEvent{JTI: fmt.Sprint(i), SET: fmt.Sprintf("set-%d", i), EnqueuedAt: time.Unix(int64(i), 0).UTC()}
		if err := st.Enqueue(ctx, "s1", e, 0); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := st.PendingEvents(ctx, "s1", 0, false)
	if len(all) != 3 || all[0].JTI != "0" || all[2].SET != "set-2" {
		t.Errorf("PendingEvents = %+v, want three in order", all)
	}
	first, _ := st.PendingEvents(ctx, "s1", 2, false)
	if len(first) != 2 || first[1].JTI != "1" {
		t.Errorf("PendingEvents(max 2) = %+v", first)
	}
	if again, _ := st.PendingEvents(ctx, "s1", 0, false); len(again) != 3 {
		t.Error("PendingEvents removed events")
	}
	if other, _ := st.PendingEvents(ctx, "s2", 0, false); len(other) != 0 {
		t.Errorf("queues are not per stream: %v", other)
	}
}

func testAckAndPurge(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	for i, control := range []bool{false, true, false, true} {
		e := storage.QueuedEvent{JTI: fmt.Sprint(i), SET: "set", Control: control}
		if err := st.Enqueue(ctx, "s1", e, 0); err != nil {
			t.Fatal(err)
		}
	}
	control, _ := st.PendingEvents(ctx, "s1", 0, true)
	if len(control) != 2 || control[0].JTI != "1" || control[1].JTI != "3" {
		t.Errorf("PendingEvents(controlOnly) = %+v", control)
	}
	if one, _ := st.PendingEvents(ctx, "s1", 1, true); len(one) != 1 || one[0].JTI != "1" {
		t.Errorf("PendingEvents(max 1, controlOnly) = %+v", one)
	}
	if err := st.AckEvents(ctx, "s1", []string{"0", "unknown", "0"}); err != nil {
		t.Fatal(err)
	}
	if q, _ := st.PendingEvents(ctx, "s1", 0, false); len(q) != 3 || q[0].JTI != "1" {
		t.Errorf("after ack: %+v", q)
	}
	if err := st.PurgeEvents(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if q, _ := st.PendingEvents(ctx, "s1", 0, false); len(q) != 0 {
		t.Errorf("after purge: %+v, want an empty queue", q)
	}
}

func testConcurrentUpdates(t *testing.T, st storage.StreamStore) {
	mustCreate(t, st, sampleStream("s1", "r1"))
	const n = 50
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, err := st.UpdateStream(ctx, "s1", func(s *storage.Stream) error {
				s.EventsRequested = append(s.EventsRequested, ssf.EventType(fmt.Sprint(i)))
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	got, _ := st.Stream(ctx, "s1")
	if len(got.EventsRequested) != 2+n {
		t.Errorf("lost updates: %d events requested, want %d", len(got.EventsRequested), 2+n)
	}
}

func streamsEqual(a, b storage.Stream) bool {
	return a.CreatedAt.Equal(b.CreatedAt) && a.LastVerificationRequest.Equal(b.LastVerificationRequest) &&
		a.LastActivity.Equal(b.LastActivity) && reflect.DeepEqual(withoutTimes(a), withoutTimes(b))
}

func withoutTimes(s storage.Stream) storage.Stream {
	s.CreatedAt, s.LastVerificationRequest, s.LastActivity = time.Time{}, time.Time{}, time.Time{}
	return s
}

// ReplayStore runs the storage.ReplayStore contract against stores made by
// newStore. Each subtest gets a fresh, empty store.
func ReplayStore(t *testing.T, newStore func(t *testing.T) storage.ReplayStore) {
	far := time.Now().Add(time.Hour)
	t.Run("MarkOnce", func(t *testing.T) {
		st := newStore(t)
		if fresh, err := st.MarkSET(ctx, "https://iss", "1", far); err != nil || !fresh {
			t.Fatalf("first mark = %v, %v", fresh, err)
		}
		if fresh, err := st.MarkSET(ctx, "https://iss", "1", far); err != nil || fresh {
			t.Errorf("second mark = %v, %v; want not fresh", fresh, err)
		}
		if fresh, _ := st.MarkSET(ctx, "https://other", "1", far); !fresh {
			t.Error("the same jti from another issuer was treated as a replay")
		}
	})
	t.Run("Forget", func(t *testing.T) {
		st := newStore(t)
		_, _ = st.MarkSET(ctx, "https://iss", "1", far)
		if err := st.ForgetSET(ctx, "https://iss", "1"); err != nil {
			t.Fatal(err)
		}
		if fresh, _ := st.MarkSET(ctx, "https://iss", "1", far); !fresh {
			t.Error("a forgotten SET is still recorded")
		}
		if err := st.ForgetSET(ctx, "https://iss", "unknown"); err != nil {
			t.Errorf("forgetting an unknown SET: %v", err)
		}
	})
	t.Run("Expiry", func(t *testing.T) {
		st := newStore(t)
		_, _ = st.MarkSET(ctx, "https://iss", "1", time.Now().Add(-time.Second))
		if fresh, _ := st.MarkSET(ctx, "https://iss", "1", far); !fresh {
			t.Error("an expired record still blocks the SET")
		}
	})
	t.Run("Concurrent", func(t *testing.T) {
		st := newStore(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		fresh := 0
		for range 50 {
			wg.Go(func() {
				ok, err := st.MarkSET(ctx, "https://iss", "race", far)
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					fresh++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if fresh != 1 {
			t.Errorf("%d concurrent marks succeeded, want exactly 1", fresh)
		}
	})
}

// RevocationStore runs the storage.RevocationStore contract against stores
// from newStore.
func RevocationStore(t *testing.T, newStore func(t *testing.T) storage.RevocationStore) {
	now := time.Now()
	user := storage.RevocationKey{Kind: storage.RevokeUser, Issuer: "https://idp.example", Value: "alice"}
	t.Run("RevokeAndRead", func(t *testing.T) {
		st := newStore(t)
		if _, ok, err := st.RevokedAt(ctx, user, now); err != nil || ok {
			t.Fatalf("before any revocation: %v, %v", ok, err)
		}
		if err := st.Revoke(ctx, user, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		at, ok, err := st.RevokedAt(ctx, user, now)
		if err != nil || !ok || !at.Equal(now) {
			t.Errorf("RevokedAt = %v, %v, %v; want %v", at, ok, err, now)
		}
		for _, other := range []storage.RevocationKey{
			{Kind: storage.RevokeSession, Issuer: user.Issuer, Value: user.Value},
			{Kind: storage.RevokeUser, Issuer: "https://other.example", Value: user.Value},
			{Kind: storage.RevokeUser, Issuer: user.Issuer, Value: "bob"},
		} {
			if _, ok, _ := st.RevokedAt(ctx, other, now); ok {
				t.Errorf("%+v is revoked too", other)
			}
		}
	})
	t.Run("KeepsTheLaterTimes", func(t *testing.T) {
		st := newStore(t)
		_ = st.Revoke(ctx, user, now, now.Add(2*time.Hour))
		_ = st.Revoke(ctx, user, now.Add(-time.Minute), now.Add(time.Hour))
		at, ok, _ := st.RevokedAt(ctx, user, now.Add(90*time.Minute))
		if !ok || !at.Equal(now) {
			t.Errorf("an earlier revocation replaced a later one, or shortened its expiry: %v, %v", at, ok)
		}
		_ = st.Revoke(ctx, user, now.Add(time.Minute), now.Add(time.Hour))
		if at, _, _ := st.RevokedAt(ctx, user, now); !at.Equal(now.Add(time.Minute)) {
			t.Errorf("a later revocation was not recorded: %v", at)
		}
	})
	t.Run("Expires", func(t *testing.T) {
		st := newStore(t)
		_ = st.Revoke(ctx, user, now, now.Add(time.Hour))
		if _, ok, _ := st.RevokedAt(ctx, user, now.Add(time.Hour)); ok {
			t.Error("a revocation outlived its expiry")
		}
	})
	t.Run("FarFutureExpiry", func(t *testing.T) {
		// An expiry beyond what a store can represent must not wrap into
		// the past and silently drop the revocation.
		st := newStore(t)
		if err := st.Revoke(ctx, user, now, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := st.RevokedAt(ctx, user, now); err != nil || !ok {
			t.Errorf("a revocation expiring in the year 3000 is not in force: %v, %v", ok, err)
		}
	})
}
