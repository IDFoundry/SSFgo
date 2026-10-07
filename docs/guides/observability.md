# Observability in Go

Each role reports what it does through `Hooks` in its configuration —
optional callbacks, as `net/http/httptrace` uses — so you can feed
metrics or traces into whatever system you run, without SSFgo importing
any metrics library. Both roles also answer readiness probes with
`Ready`.

## What each role reports

| Hook | Called | With |
|---|---|---|
| `receiver.Hooks.SET` | for every SET pushed or polled | its outcome — handled, duplicate, rejected with its RFC 8935 code, failed — and how long it took |
| `receiver.Hooks.Poll` | after every poll request | SETs received, duration, error |
| `receiver.Hooks.KeysRefreshed` | after every JWKS refetch | nil, or why it failed |
| `transmitter.Hooks.Emit` | after every `Emit` | streams considered and queued on |
| `transmitter.Hooks.Push` | after every push attempt | delivered, rejected, retry or dropped; attempt; latency |
| `transmitter.Hooks.Poll` | after every poll a Receiver makes | SETs returned, acknowledged, reported |
| `transmitter.Hooks.Stream` | after a stream changes | created, updated, status changed, deleted |

## Metrics

Count by the bounded fields — event type, outcome, error code — and
never by text: a field marked untrusted, such as `SETInfo.Err` or
`PushInfo.Detail`, carries what the other party wrote. Log it instead.

```go
rxCfg.Hooks = receiver.Hooks{
	SET: func(ctx context.Context, i receiver.SETInfo) {
		metrics.Count("ssf_sets_total", string(i.EventType), i.Outcome.String(), i.ErrorCode) // yours
		metrics.Observe("ssf_set_seconds", i.Duration.Seconds())
		if i.Err != nil {
			slog.WarnContext(ctx, "SSF SET not handled", "jti", i.JTI, "error", i.Err)
		}
	},
}
txCfg.Hooks = transmitter.Hooks{
	Push: func(ctx context.Context, i transmitter.PushInfo) {
		metrics.Count("ssf_push_attempts_total", i.Outcome.String())
		metrics.Observe("ssf_push_seconds", i.Duration.Seconds())
	},
}
```

Hooks run on the goroutine of the work they report, once it is done, so
they must not block: hand slow work to another goroutine. A hook that
panics is recovered and logged, so a bug in one cannot stop delivery or
crash the process.

## Readiness

```go
http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
	if err := rx.Ready(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
})
```

A Receiver is ready when it holds the Transmitter's keys, fetched within
`Limits.KeyMaxAge`; overdue keys are refetched first, at most once a
minute, so a public probe cannot cause a fetch storm. A Transmitter is
ready when its store answers.
