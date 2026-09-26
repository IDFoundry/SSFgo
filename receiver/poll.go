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
	// return more.
	MoreAvailable bool
}

// Poll makes one poll request on a poll-delivery stream (RFC 8936). It
// acknowledges the SETs processed by the previous poll and reports the
// ones rejected, then verifies and handles every SET returned. Their
// acknowledgements go out with the next Poll or Acknowledge. A SET whose
// handler fails is neither acknowledged nor reported, so the Transmitter
// returns it again.
func (r *Receiver) Poll(ctx context.Context, stream ssf.StreamConfiguration, opts PollOptions) (PollResult, error) {
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
	for jti, token := range resp.Sets {
		got, err := r.process(ctx, token)
		if got == "" {
			got = jti
		}
		if rej, ok := isRejection(err); ok {
			r.cfg.Logger.WarnContext(ctx, "ssf receiver: rejected polled SET", "jti", got, "err", rej.code, "description", rej.description)
			r.queueAck(stream.StreamID, "", got, &setErr{Err: rej.code, Description: rej.description})
			continue
		}
		if err != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: handling polled SET failed", "jti", got, "error", err)
			continue
		}
		r.queueAck(stream.StreamID, got, "", nil)
	}
	return PollResult{Received: len(resp.Sets), MoreAvailable: resp.MoreAvailable}, nil
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
