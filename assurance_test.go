package ssf

import "testing"

// The zero Assurance is invalid, so a level left unset is refused.
func TestAssurance(t *testing.T) {
	for a, want := range map[Assurance]string{
		0:                    "Assurance(0)",
		AssuranceDevelopment: "development",
		AssuranceProduction:  "production",
		3:                    "Assurance(3)",
	} {
		if a.String() != want || a.IsValid() != (a == AssuranceDevelopment || a == AssuranceProduction) {
			t.Errorf("Assurance %d: String %q, IsValid %v", a, a.String(), a.IsValid())
		}
	}
	var unset Assurance
	if unset.IsValid() {
		t.Error("the zero Assurance is valid")
	}
}
