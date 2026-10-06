// Package peertext makes text from the other party — a Transmitter's
// error body, a Receiver's rejection, a header member of a SET anyone
// could push — safe to log, return or report to a hook: cut to a bound
// the caller names, with anything but printable ASCII replaced, so it can
// neither flood a log nor forge or disguise a line of one.
package peertext

import "strings"

// Clean returns s with every byte outside printable ASCII replaced by
// '?', cut to at most limit bytes (marked with "..."); limit is at least 3.
func Clean(s string, limit int) string {
	cut := len(s) > limit
	if cut {
		s = s[:max(limit-3, 0)]
	}
	var b strings.Builder
	b.Grow(len(s) + 3)
	for i := range len(s) {
		if c := s[i]; c >= ' ' && c <= '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	if cut {
		b.WriteString("...")
	}
	return b.String()
}
