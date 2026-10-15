package storage_test

import (
	"testing"

	"github.com/idfoundry/ssfgo/storage"
)

func TestClaimOutcomeString(t *testing.T) {
	for o, want := range map[storage.ClaimOutcome]string{
		storage.ClaimAcquired: "ClaimAcquired",
		storage.ClaimHeld:     "ClaimHeld",
		storage.ClaimDone:     "ClaimDone",
		0:                     "ClaimOutcome(0)",
		9:                     "ClaimOutcome(9)",
	} {
		if got := o.String(); got != want {
			t.Errorf("ClaimOutcome %d = %q, want %q", uint8(o), got, want)
		}
	}
}
