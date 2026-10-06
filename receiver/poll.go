package receiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	ssf "github.com/idfoundry/ssfgo"
)

// pendingAcks holds what the next poll on a stream reports back.
type pendingAcks struct {
	ack  []string
	errs map[string]setErr
}

type setErr struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

type pollRequest struct {
	MaxEvents         *int              `json:"maxEvents,omitempty"`
	ReturnImmediately bool              `json:"returnImmediately"`
	Ack               []string          `json:"ack,omitempty"`
	SetErrs           map[string]setErr `json:"setErrs,omitempty"`
}

type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// Bounds on what one poll response can make the Receiver do, whatever the
// Transmitter sends: SETs beyond maxPolledSETs (or PollOptions.MaxEvents)
// are left unacknowledged for the Transmitter to deliver again, and
// rejections beyond maxRejectionLogs are logged as a count.
const (
	maxPolledSETs    = 1000
	maxRejectionLogs = 10
)

// emptyPollPause is the least time between two of RunPoller's long polls
// that return nothing, so a Transmitter that answers at once rather than
// holding the request does not get polled in a busy loop.
var emptyPollPause = time.Second

// PollOptions shapes one poll request (RFC 8936 §2.2).
type PollOptions struct {
	// MaxEvents limits how many SETs are returned; zero means no limit.
	MaxEvents int
	// Wait asks the Transmitter to hold the request until a SET is
	// available (a long poll) instead of returning immediately.
	Wait bool
}

// PollResult reports one poll.
type PollResult struct {
	// Received is how many SETs the Transmitter returned.
	Received int
	// MoreAvailable is the Transmitter's hint that another poll would
	// return more. It is also set when the response held more SETs than
	// the Receiver handles from one poll, which it leaves to be delivered
	// again.
	MoreAvailable bool
}

// Poll makes one poll request on a poll-delivery stream (RFC 8936). It
// acknowledges the SETs processed by the previous poll and reports the
// ones rejected, then verifies and handles every SET returned. Their
// acknowledgements go out with the next Poll or Acknowledge. A SET whose
// handler fails is neither acknowledged nor reported, so the Transmitter
// returns it again.
func (r *Receiver) Poll(ctx context.Context, stream ssf.StreamConfiguration, opts PollOptions) (PollResult, error) {
	start := r.cfg.Now()
	res, err := r.poll(ctx, stream, opts)
	if r.cfg.Hooks.Poll != nil {
		r.observe(ctx, "Poll", func() {
			r.cfg.Hooks.Poll(ctx, PollInfo{StreamID: stream.StreamID, Received: res.Received, Duration: r.cfg.Now().Sub(start), Err: err})
		})
	}
	return res, err
}

// poll is Poll without reporting it.
func (r *Receiver) poll(ctx context.Context, stream ssf.StreamConfiguration, opts PollOptions) (PollResult, error) {
	if stream.Delivery.Method != ssf.DeliveryPoll || stream.Delivery.EndpointURL == "" {
		return PollResult{}, errors.New("receiver: the stream does not use poll delivery")
	}
	if u, err := url.Parse(stream.Delivery.EndpointURL); err != nil || u.Scheme != "https" {
		return PollResult{}, fmt.Errorf("receiver: poll endpoint %q is not an https URL", stream.Delivery.EndpointURL)
	}
	req := pollRequest{ReturnImmediately: !opts.Wait}
	if opts.MaxEvents > 0 {
		req.MaxEvents = &opts.MaxEvents
	}
	pending := r.takeAcks(stream.StreamID)
	req.Ack, req.SetErrs = pending.ack, pending.errs

	var resp pollResponse
	if err := r.call(ctx, http.MethodPost, stream.Delivery.EndpointURL, req, &resp, http.StatusOK); err != nil {
		r.restoreAcks(stream.StreamID, pending)
		return PollResult{}, err
	}
	limit := maxPolledSETs
	if opts.MaxEvents > 0 {
		limit = min(opts.MaxEvents, limit)
	}
	handled := r.handlePolled(ctx, stream.StreamID, resp.Sets, limit)
	return PollResult{Received: len(resp.Sets), MoreAvailable: resp.MoreAvailable || handled < len(resp.Sets)}, nil
}

// handlePolled processes up to limit of a poll response's SETs, queuing
// their acknowledgements and errors for the next poll. It returns how
// many it processed.
func (r *Receiver) handlePolled(ctx context.Context, streamID string, sets map[string]string, limit int) int {
	handled, rejected := 0, 0
	for jti, token := range sets {
		if handled == limit {
			break
		}
		handled++
		got, err := r.processObserved(ctx, ssf.DeliveryPoll, token)
		if got == "" {
			got = jti
		}
		rej, isRejected := isRejection(err)
		switch {
		case isRejected:
			if rejected++; rejected <= maxRejectionLogs {
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: rejected polled SET", "jti", got, "err", rej.code, "description", rej.description)
			}
			r.queueAck(streamID, "", got, &setErr{Err: rej.code, Description: rej.description})
		case err != nil:
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: handling polled SET failed", "jti", got, "error", err)
		default:
			r.queueAck(streamID, got, "", nil)
		}
	}
	if rejected > maxRejectionLogs {
		r.cfg.Logger.WarnContext(ctx, "ssf receiver: more polled SETs rejected", "stream_id", streamID, "count", rejected-maxRejectionLogs)
	}
	return handled
}

// Acknowledge sends any pending acknowledgements for a stream without
// asking for more SETs (RFC 8936 §2.4.2). Call it before deleting a
// stream or stopping, so the Transmitter does not redeliver.
func (r *Receiver) Acknowledge(ctx context.Context, stream ssf.StreamConfiguration) error {
	pending := r.takeAcks(stream.StreamID)
	if len(pending.ack) == 0 && len(pending.errs) == 0 {
		return nil
	}
	zero := 0
	req := pollRequest{MaxEvents: &zero, ReturnImmediately: true, Ack: pending.ack, SetErrs: pending.errs}
	if err := r.call(ctx, http.MethodPost, stream.Delivery.EndpointURL, req, nil, http.StatusOK); err != nil {
		r.restoreAcks(stream.StreamID, pending)
		return err
	}
	return nil
}

// RunPoller long-polls a stream until ctx is done, then acknowledges what
// it processed and returns ctx.Err(). Failed polls are logged and retried
// after a pause.
func (r *Receiver) RunPoller(ctx context.Context, stream ssf.StreamConfiguration) error {
	for ctx.Err() == nil {
		start := time.Now()
		res, err := r.Poll(ctx, stream, PollOptions{Wait: true})
		if err != nil && ctx.Err() == nil {
			r.cfg.Logger.WarnContext(ctx, "ssf receiver: poll failed", "stream_id", stream.StreamID, "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if res.Received == 0 && !res.MoreAvailable {
			// Keep acknowledgements flowing even when nothing new arrives.
			_ = r.Acknowledge(ctx, stream)
			select {
			case <-ctx.Done():
			case <-time.After(emptyPollPause - time.Since(start)):
			}
		}
	}
	flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = r.Acknowledge(flush, stream)
	return ctx.Err()
}

func (r *Receiver) takeAcks(streamID string) pendingAcks {
	r.pollMu.Lock()
	defer r.pollMu.Unlock()
	p := r.acks[streamID]
	delete(r.acks, streamID)
	if p == nil {
		return pendingAcks{}
	}
	return *p
}

func (r *Receiver) restoreAcks(streamID string, p pendingAcks) {
	for _, jti := range p.ack {
		r.queueAck(streamID, jti, "", nil)
	}
	for jti, e := range p.errs {
		r.queueAck(streamID, "", jti, &e)
	}
}

func (r *Receiver) queueAck(streamID, ackJTI, errJTI string, e *setErr) {
	r.pollMu.Lock()
	defer r.pollMu.Unlock()
	p := r.acks[streamID]
	if p == nil {
		p = &pendingAcks{}
		r.acks[streamID] = p
	}
	if ackJTI != "" {
		p.ack = append(p.ack, ackJTI)
	}
	if e != nil {
		if p.errs == nil {
			p.errs = map[string]setErr{}
		}
		p.errs[errJTI] = *e
	}
}
