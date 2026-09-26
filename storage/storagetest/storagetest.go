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
		{"SingleStreamPerReceiver", testSingleStreamPerReceiver},
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
		Delivery:        ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: "https://rx.example.com/events", AuthorizationHeader: "Bearer x"},
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
	single := storage.CreateOptions{SingleStreamPerReceiver: true}
	if err := st.CreateStream(ctx, sampleStream("s1", "r1"), single); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateStream(ctx, sampleStream("s2", "r1"), single); !errors.Is(err, storage.ErrReceiverHasStream) {
		t.Errorf("second stream for r1 = %v, want ErrReceiverHasStream", err)
	}
	if err := st.CreateStream(ctx, sampleStream("s3", "r2"), single); err != nil {
		t.Errorf("first stream for r2: %v", err)
	}
	if err := st.CreateStream(ctx, sampleStream("s4", "r1"), storage.CreateOptions{}); err != nil {
		t.Errorf("without the option a receiver may own several streams: %v", err)
	}
	if err := st.DeleteStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteStream(ctx, "s4"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateStream(ctx, sampleStream("s5", "r1"), single); err != nil {
		t.Errorf("after deleting r1's streams: %v", err)
	}
}

func testNotFound(t *testing.T, st storage.StreamStore) {
	calls := map[string]error{}
	_, calls["Stream"] = st.Stream(ctx, "nope")
	_, calls["UpdateStream"] = st.UpdateStream(ctx, "nope", func(*storage.Stream) error { return nil })
	calls["DeleteStream"] = st.DeleteStream(ctx, "nope")
	calls["SetSubjectRule"] = st.SetSubjectRule(ctx, "nope", storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "x"}})
	_, calls["SubjectRules"] = st.SubjectRules(ctx, "nope")
	calls["Enqueue"] = st.Enqueue(ctx, "nope", storage.QueuedEvent{JTI: "1", SET: "x"})
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
	if err := st.SetSubjectRule(ctx, "s1", storage.SubjectRule{Subject: ssf.OpaqueSubject{ID: "x"}, Included: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: "1", SET: "a.b.c"}); err != nil {
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
	for _, r := range []storage.SubjectRule{
		{Subject: a, Included: true},
		{Subject: b, Included: true},
		{Subject: a, Included: false},
		{Subject: bReordered, Included: true},
	} {
		if err := st.SetSubjectRule(ctx, "s1", r); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := st.SubjectRules(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("SubjectRules = %v, want one rule per distinct subject", rules)
	}
	if !ssf.SubjectsEqual(rules[0].Subject, a) || rules[0].Included {
		t.Errorf("rule 0 = %+v, want a excluded (replaced in place)", rules[0])
	}
	if !ssf.SubjectsEqual(rules[1].Subject, b) || !rules[1].Included {
		t.Errorf("rule 1 = %+v, want b included", rules[1])
	}
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
		if err := st.Enqueue(ctx, "s1", e); err != nil {
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
		if err := st.Enqueue(ctx, "s1", e); err != nil {
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
		reflect.DeepEqual(withoutTimes(a), withoutTimes(b))
}

func withoutTimes(s storage.Stream) storage.Stream {
	s.CreatedAt, s.LastVerificationRequest = time.Time{}, time.Time{}
	return s
}
