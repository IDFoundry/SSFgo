package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// StreamStore implements storage.StreamStore.
type StreamStore struct {
	db *sql.DB
	d  Dialect
}

var _ storage.StreamStore = (*StreamStore)(nil)

// NewStreamStore returns a StreamStore on db, whose schema CreateSchema has
// created or migrated. It fails if the database's schema version is not
// SchemaVersion, so a database left unmigrated is found at startup rather
// than at the first query that needs what changed.
func NewStreamStore(ctx context.Context, db *sql.DB, d Dialect) (*StreamStore, error) {
	if err := d.check(db); err != nil {
		return nil, err
	}
	if err := checkSchema(ctx, db); err != nil {
		return nil, err
	}
	return &StreamStore{db: db, d: d}, nil
}

const streamColumns = `id, receiver_id, audience, delivery, events_requested, events_delivered,
	description, status, status_reason, status_locked, last_verification_request, last_activity, created_at`

// streamRow is a stream as stored.
type streamRow struct {
	id, receiverID                            string
	audience, delivery, requested, delivered  string
	description, status, statusReason         string
	statusLocked                              bool
	lastVerification, lastActivity, createdAt sql.NullInt64
}

func toRow(s storage.Stream) (streamRow, error) {
	r := streamRow{
		id: s.ID, receiverID: s.ReceiverID, description: s.Description,
		status: string(s.Status), statusReason: s.StatusReason, statusLocked: s.StatusSetByTransmitter,
		lastVerification: nanos(s.LastVerificationRequest), lastActivity: nanos(s.LastActivity), createdAt: nanos(s.CreatedAt),
	}
	for _, f := range []struct {
		dst *string
		v   any
	}{{&r.audience, s.Audience}, {&r.delivery, s.Delivery}, {&r.requested, s.EventsRequested}, {&r.delivered, s.EventsDelivered}} {
		b, err := json.Marshal(f.v)
		if err != nil {
			return streamRow{}, err
		}
		*f.dst = string(b)
	}
	return r, nil
}

func (r streamRow) args() []any {
	return []any{r.id, r.receiverID, r.audience, r.delivery, r.requested, r.delivered,
		r.description, r.status, r.statusReason, r.statusLocked, r.lastVerification, r.lastActivity, r.createdAt}
}

func (r *streamRow) dests() []any {
	return []any{&r.id, &r.receiverID, &r.audience, &r.delivery, &r.requested, &r.delivered,
		&r.description, &r.status, &r.statusReason, &r.statusLocked, &r.lastVerification, &r.lastActivity, &r.createdAt}
}

func (r streamRow) stream() (storage.Stream, error) {
	s := storage.Stream{
		ID: r.id, ReceiverID: r.receiverID, Description: r.description,
		Status: ssf.StreamStatus(r.status), StatusReason: r.statusReason, StatusSetByTransmitter: r.statusLocked,
		LastVerificationRequest: fromNanos(r.lastVerification), LastActivity: fromNanos(r.lastActivity), CreatedAt: fromNanos(r.createdAt),
	}
	for _, f := range []struct {
		src string
		dst any
	}{{r.audience, &s.Audience}, {r.delivery, &s.Delivery}, {r.requested, &s.EventsRequested}, {r.delivered, &s.EventsDelivered}} {
		if err := json.Unmarshal([]byte(f.src), f.dst); err != nil {
			return storage.Stream{}, fmt.Errorf("sqlstore: stream %s: %w", r.id, err)
		}
	}
	return s, nil
}

func nanos(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixNano(), Valid: true}
}

func fromNanos(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

// CreateStream implements storage.StreamStore.
func (m *StreamStore) CreateStream(ctx context.Context, s storage.Stream, opts storage.CreateOptions) error {
	row, err := toRow(s)
	if err != nil {
		return err
	}
	return m.d.inTx(ctx, m.db, func(q querier) error {
		if opts.MaxStreamsPerReceiver > 0 {
			if err := m.checkStreamLimit(ctx, q, s.ReceiverID, opts.MaxStreamsPerReceiver); err != nil {
				return err
			}
		}
		res, err := q.ExecContext(ctx, m.d.rebind(`INSERT INTO ssf_streams (`+streamColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`), row.args()...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return storage.ErrExists
		}
		return nil
	})
}

// checkStreamLimit returns storage.ErrTooManyStreams if receiverID already
// owns limit streams. It locks the Receiver first, so the count stays true
// until the transaction ends.
func (m *StreamStore) checkStreamLimit(ctx context.Context, q querier, receiverID string, limit int) error {
	if err := m.d.lockReceiver(ctx, q, receiverID); err != nil {
		return err
	}
	var owned int
	if err := q.QueryRowContext(ctx, m.d.rebind(`SELECT COUNT(*) FROM ssf_streams WHERE receiver_id = ?`), receiverID).Scan(&owned); err != nil {
		return err
	}
	if owned >= limit {
		return storage.ErrTooManyStreams
	}
	return nil
}

// Stream implements storage.StreamStore.
func (m *StreamStore) Stream(ctx context.Context, id string) (storage.Stream, error) {
	return m.get(ctx, m.db, id, false)
}

// get reads one stream, locking its row if lock is set.
func (m *StreamStore) get(ctx context.Context, q querier, id string, lock bool) (storage.Stream, error) {
	query := `SELECT ` + streamColumns + ` FROM ssf_streams WHERE id = ?`
	if lock {
		query += m.d.forUpdate()
	}
	var r streamRow
	err := q.QueryRowContext(ctx, m.d.rebind(query), id).Scan(r.dests()...)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.Stream{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Stream{}, err
	}
	return r.stream()
}

// StreamsForReceiver implements storage.StreamStore.
func (m *StreamStore) StreamsForReceiver(ctx context.Context, receiverID string) ([]storage.Stream, error) {
	return m.list(ctx, `SELECT `+streamColumns+` FROM ssf_streams WHERE receiver_id = ? ORDER BY seq`, receiverID)
}

// AllStreams implements storage.StreamStore.
func (m *StreamStore) AllStreams(ctx context.Context) ([]storage.Stream, error) {
	return m.list(ctx, `SELECT `+streamColumns+` FROM ssf_streams ORDER BY seq`)
}

func (m *StreamStore) list(ctx context.Context, query string, args ...any) ([]storage.Stream, error) {
	rows, err := m.db.QueryContext(ctx, m.d.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []storage.Stream{}
	for rows.Next() {
		var r streamRow
		if err := rows.Scan(r.dests()...); err != nil {
			return nil, err
		}
		s, err := r.stream()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateStream implements storage.StreamStore.
func (m *StreamStore) UpdateStream(ctx context.Context, id string, update func(*storage.Stream) error) (storage.Stream, error) {
	var updated storage.Stream
	err := m.d.inTx(ctx, m.db, func(q querier) error {
		s, err := m.get(ctx, q, id, true)
		if err != nil {
			return err
		}
		if err := update(&s); err != nil {
			return err
		}
		s.ID = id
		row, err := toRow(s)
		if err != nil {
			return err
		}
		// Every column but id, which the update may not change.
		_, err = q.ExecContext(ctx, m.d.rebind(`UPDATE ssf_streams SET receiver_id = ?, audience = ?, delivery = ?,
			events_requested = ?, events_delivered = ?, description = ?, status = ?, status_reason = ?,
			status_locked = ?, last_verification_request = ?, last_activity = ?, created_at = ? WHERE id = ?`),
			append(row.args()[1:], id)...)
		updated = s
		return err
	})
	if err != nil {
		return storage.Stream{}, err
	}
	return updated, nil
}

// DeleteStream implements storage.StreamStore.
func (m *StreamStore) DeleteStream(ctx context.Context, id string) error {
	return m.d.inTx(ctx, m.db, func(q querier) error {
		res, err := q.ExecContext(ctx, m.d.rebind(`DELETE FROM ssf_streams WHERE id = ?`), id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return storage.ErrNotFound
		}
		for _, table := range []string{"ssf_subject_rules", "ssf_events"} {
			if _, err := q.ExecContext(ctx, m.d.rebind(`DELETE FROM `+table+` WHERE stream_id = ?`), id); err != nil {
				return err
			}
		}
		return nil
	})
}

// lock locks a stream's row until the transaction ends, or returns
// storage.ErrNotFound. Every write to a stream's subject rules or queue
// takes it first, so a concurrent DeleteStream cannot leave orphans.
func (m *StreamStore) lock(ctx context.Context, q querier, id string) error {
	var one int
	err := q.QueryRowContext(ctx, m.d.rebind(`SELECT 1 FROM ssf_streams WHERE id = ?`+m.d.forUpdate()), id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	return err
}

// exists returns storage.ErrNotFound if the stream does not exist.
func (m *StreamStore) exists(ctx context.Context, id string) error {
	var one int
	err := m.db.QueryRowContext(ctx, m.d.rebind(`SELECT 1 FROM ssf_streams WHERE id = ?`), id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	return err
}

// SetSubjectRule implements storage.StreamStore.
func (m *StreamStore) SetSubjectRule(ctx context.Context, streamID string, rule storage.SubjectRule, maxRules int) error {
	if rule.Subject == nil {
		return errors.New("sqlstore: subject rule has no subject")
	}
	subject, err := json.Marshal(rule.Subject)
	if err != nil {
		return err
	}
	return m.d.inTx(ctx, m.db, func(q querier) error {
		if err := m.lock(ctx, q, streamID); err != nil {
			return err
		}
		rules, seqs, err := m.rules(ctx, q, streamID)
		if err != nil {
			return err
		}
		// Subjects are compared with ssf.SubjectsEqual, not as stored
		// JSON: equal subjects can be encoded differently.
		for i, have := range rules {
			if ssf.SubjectsEqual(have.Subject, rule.Subject) {
				// Re-insert rather than update, so the rule takes a new,
				// highest seq and is the newest.
				if _, err := q.ExecContext(ctx, m.d.rebind(`DELETE FROM ssf_subject_rules WHERE seq = ?`), seqs[i]); err != nil {
					return err
				}
				return m.insertRule(ctx, q, streamID, subject, rule.Included)
			}
		}
		if maxRules > 0 && len(rules) >= maxRules {
			return storage.ErrTooManySubjectRules
		}
		return m.insertRule(ctx, q, streamID, subject, rule.Included)
	})
}

func (m *StreamStore) insertRule(ctx context.Context, q querier, streamID string, subject []byte, included bool) error {
	_, err := q.ExecContext(ctx, m.d.rebind(`INSERT INTO ssf_subject_rules (stream_id, subject, included) VALUES (?, ?, ?)`),
		streamID, string(subject), included)
	return err
}

// SubjectRules implements storage.StreamStore.
func (m *StreamStore) SubjectRules(ctx context.Context, streamID string) ([]storage.SubjectRule, error) {
	if err := m.exists(ctx, streamID); err != nil {
		return nil, err
	}
	rules, _, err := m.rules(ctx, m.db, streamID)
	return rules, err
}

func (m *StreamStore) rules(ctx context.Context, q querier, streamID string) ([]storage.SubjectRule, []int64, error) {
	rows, err := q.QueryContext(ctx, m.d.rebind(`SELECT seq, subject, included FROM ssf_subject_rules WHERE stream_id = ? ORDER BY seq`), streamID)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	var (
		rules []storage.SubjectRule
		seqs  []int64
	)
	for rows.Next() {
		var (
			seq      int64
			subject  string
			included bool
		)
		if err := rows.Scan(&seq, &subject, &included); err != nil {
			return nil, nil, err
		}
		s, err := ssf.ParseSubject([]byte(subject))
		if err != nil {
			return nil, nil, fmt.Errorf("sqlstore: stream %s: stored subject: %w", streamID, err)
		}
		rules = append(rules, storage.SubjectRule{Subject: s, Included: included})
		seqs = append(seqs, seq)
	}
	return rules, seqs, rows.Err()
}

// Enqueue implements storage.StreamStore.
func (m *StreamStore) Enqueue(ctx context.Context, streamID string, e storage.QueuedEvent, maxQueued int) error {
	return m.d.inTx(ctx, m.db, func(q querier) error {
		if err := m.lock(ctx, q, streamID); err != nil {
			return err
		}
		if maxQueued > 0 {
			var queued int
			if err := q.QueryRowContext(ctx, m.d.rebind(`SELECT COUNT(*) FROM ssf_events WHERE stream_id = ?`), streamID).Scan(&queued); err != nil {
				return err
			}
			if queued >= maxQueued {
				return storage.ErrQueueFull
			}
		}
		_, err := q.ExecContext(ctx, m.d.rebind(`INSERT INTO ssf_events (stream_id, jti, set_token, enqueued_at, control) VALUES (?, ?, ?, ?, ?)`),
			streamID, e.JTI, e.SET, nanos(e.EnqueuedAt), e.Control)
		return err
	})
}

// PendingEvents implements storage.StreamStore.
func (m *StreamStore) PendingEvents(ctx context.Context, streamID string, limit int, controlOnly bool) ([]storage.QueuedEvent, error) {
	if err := m.exists(ctx, streamID); err != nil {
		return nil, err
	}
	query := `SELECT jti, set_token, enqueued_at, control FROM ssf_events WHERE stream_id = ?`
	args := []any{streamID}
	if controlOnly {
		query += ` AND control = ?`
		args = append(args, true)
	}
	query += ` ORDER BY seq`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := m.db.QueryContext(ctx, m.d.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []storage.QueuedEvent
	for rows.Next() {
		var (
			e  storage.QueuedEvent
			at sql.NullInt64
		)
		if err := rows.Scan(&e.JTI, &e.SET, &at, &e.Control); err != nil {
			return nil, err
		}
		e.EnqueuedAt = fromNanos(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ackBatch bounds the placeholders in one DELETE.
const ackBatch = 500

// AckEvents implements storage.StreamStore.
func (m *StreamStore) AckEvents(ctx context.Context, streamID string, jtis []string) error {
	if err := m.exists(ctx, streamID); err != nil {
		return err
	}
	for len(jtis) > 0 {
		batch := jtis[:min(len(jtis), ackBatch)]
		jtis = jtis[len(batch):]
		args := []any{streamID}
		for _, j := range batch {
			args = append(args, j)
		}
		query := `DELETE FROM ssf_events WHERE stream_id = ? AND jti IN (?` + strings.Repeat(", ?", len(batch)-1) + `)`
		if _, err := m.db.ExecContext(ctx, m.d.rebind(query), args...); err != nil {
			return err
		}
	}
	return nil
}

// PurgeEvents implements storage.StreamStore.
func (m *StreamStore) PurgeEvents(ctx context.Context, streamID string) error {
	return m.d.inTx(ctx, m.db, func(q querier) error {
		if err := m.lock(ctx, q, streamID); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, m.d.rebind(`DELETE FROM ssf_events WHERE stream_id = ?`), streamID)
		return err
	})
}
