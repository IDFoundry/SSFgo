package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuiteConfig(t *testing.T) {
	for subjects, formats := range map[string][]string{"caep": {"email", "iss_sub"}, "email": {"email"}} {
		raw, err := suiteConfig(options{audience: "https://rx.example", subjects: subjects}, "tok")
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			SSF struct {
				Stream      struct{ Audience string }        `json:"stream"`
				Subjects    struct{ Valid []map[string]any } `json:"subjects"`
				Transmitter struct {
					AccessToken string `json:"access_token"`
				} `json:"transmitter"`
			} `json:"ssf"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.SSF.Stream.Audience != "https://rx.example" || cfg.SSF.Transmitter.AccessToken != "tok" {
			t.Errorf("%s: %+v", subjects, cfg.SSF)
		}
		if len(cfg.SSF.Subjects.Valid) != len(formats) {
			t.Fatalf("%s: %d subjects, want %d", subjects, len(cfg.SSF.Subjects.Valid), len(formats))
		}
		for i, f := range formats {
			if cfg.SSF.Subjects.Valid[i]["format"] != f {
				t.Errorf("%s: subject %d = %v", subjects, i, cfg.SSF.Subjects.Valid[i])
			}
		}
	}
}

func TestPushRouter(t *testing.T) {
	p := newPushRouter()
	p.set("m1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	for path, want := range map[string]int{"/push/m1": 202, "/push/m2": 404} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("POST", path, nil))
		if rec.Code != want {
			t.Errorf("%s = %d, want %d", path, rec.Code, want)
		}
	}
	p.set("m1", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/push/m1", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("after removal: %d", rec.Code)
	}
}
