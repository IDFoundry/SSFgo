package jsonobj

import "testing"

func TestMembers(t *testing.T) {
	m, err := Members([]byte(` {"a":1, "b":{"a":2,"a":3}} `))
	if err != nil || len(m) != 2 || string(m["a"]) != "1" {
		t.Fatalf("Members = %v, %v", m, err)
	}
	for _, bad := range []string{
		`{"a":1,"a":2}`, `{"a":1,"A":2,"a":3}`, `[]`, `null`, `"x"`, `{"a":1}{}`, `{"a":1} x`, `{"a":`, ``,
	} {
		if _, err := Members([]byte(bad)); err == nil {
			t.Errorf("Members(%q) succeeded", bad)
		}
	}
}
