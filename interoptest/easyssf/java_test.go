package easyssf

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/ssfgo/ssftest"
	"github.com/idfoundry/ssfgo/transmitter"
)

// TestEasySSFJava runs easyssf's plain-Java Receiver (java/, a program
// built with Maven) against an SSFgo Transmitter, with each delivery
// method. It is skipped unless EASYSSF_JAVA names the built project:
//
//	(cd java && mvn -B -q compile dependency:copy-dependencies)
//	EASYSSF_JAVA=$PWD/java go test -run TestEasySSFJava .
func TestEasySSFJava(t *testing.T) {
	dir := os.Getenv("EASYSSF_JAVA")
	if dir == "" {
		t.Skip("EASYSSF_JAVA is not set")
	}
	for _, delivery := range []string{"push", "poll"} {
		t.Run(delivery, func(t *testing.T) {
			// The endpoint the Transmitter pushes to is served here, as an
			// application's web framework would, and each request handed to
			// easyssf's push handler in the Java process.
			var p *javaPeer
			push := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				if err != nil || r.Method != http.MethodPost || r.URL.Path != "/ssf/push" {
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				status, reply := p.push(t, r.Header.Get("Authorization"), body)
				if reply != "" {
					w.Header().Set("Content-Type", "application/json")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, reply)
			}))
			t.Cleanup(push.Close)
			tx := ssftest.NewTransmitter(t, func(c *transmitter.Config) { c.HTTPClient = push.Client() })

			p = startJavaPeer(t, dir, tx, delivery, push.URL+"/ssf/push")
			run(t, tx, p, delivery)
		})
	}
}

// javaLine is a line the Java program writes; see Peer.java.
type javaLine struct {
	Stream     string `json:"stream"`
	Verified   bool   `json:"verified"`
	PushStatus int    `json:"push_status"`
	PushBody   string `json:"push_body"`
	Error      string `json:"error"`
	received
}

// javaPeer is the Java program, running easyssf's Receiver.
type javaPeer struct {
	stdin    io.WriteCloser
	mu       sync.Mutex // one command at a time on stdin
	streams  chan string
	verified chan struct{}
	pushed   chan javaLine
	got      chan received
	failed   chan string
	stop     func()
}

func startJavaPeer(t *testing.T, dir string, tx *ssftest.Transmitter, delivery, pushURL string) *javaPeer {
	t.Helper()
	token, err := tx.ReceiverConfig(nil).TokenSource.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "transmitter.pem")
	if err := os.WriteFile(ca, transmitterRoot(t, tx), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("java", "-cp",
		filepath.Join(dir, "target", "classes")+string(os.PathListSeparator)+filepath.Join(dir, "target", "lib", "*"),
		"dev.idfoundry.ssfgo.interop.Peer")
	cmd.Env = append(os.Environ(),
		"SSF_ISSUER="+tx.Issuer(),
		"SSF_TOKEN="+token,
		"SSF_CA="+ca,
		"SSF_DELIVERY="+delivery,
		"SSF_PUSH_URL="+pushURL,
		"SSF_PUSH_AUTH=Bearer push-"+strings.ReplaceAll(t.Name(), "/", "-"))
	cmd.Stderr = testWriter{t}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &javaPeer{
		streams:  make(chan string, 1),
		verified: make(chan struct{}, 1),
		pushed:   make(chan javaLine),
		got:      make(chan received, len(events)),
		failed:   make(chan string, 1),
	}
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting java: %v", err)
	}
	done := make(chan struct{})
	go p.read(t, stdout, done)
	p.stop = sync.OnceFunc(func() {
		// The end of stdin stops the program, which deletes its stream.
		p.mu.Lock()
		_ = p.stdin.Close()
		p.mu.Unlock()
		select {
		case <-done:
		case <-time.After(waitTimeout):
			_ = cmd.Process.Kill()
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("the Java program: %v", err)
		}
	})
	t.Cleanup(p.stop)
	return p
}

func (p *javaPeer) Stop(*testing.T) { p.stop() }

// read sorts the program's lines onto their channels.
func (p *javaPeer) read(t *testing.T, stdout io.Reader, done chan<- struct{}) {
	defer close(done)
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var l javaLine
		if err := json.Unmarshal(lines.Bytes(), &l); err != nil {
			t.Logf("java: %s", lines.Text())
			continue
		}
		switch {
		case l.Error != "":
			p.failed <- l.Error
		case l.Stream != "":
			p.streams <- l.Stream
		case l.Verified:
			p.verified <- struct{}{}
		case l.PushStatus != 0:
			p.pushed <- l
		case l.EventType != "":
			p.got <- l.received
		}
	}
}

func (p *javaPeer) StreamID(t *testing.T) string {
	t.Helper()
	select {
	case id := <-p.streams:
		return id
	case msg := <-p.failed:
		t.Fatalf("easyssf-java: %s", msg)
	case <-time.After(waitTimeout):
		t.Fatal("easyssf-java registered no stream")
	}
	return ""
}

func (p *javaPeer) Verify(t *testing.T) {
	t.Helper()
	p.send(t, "verify")
	select {
	case <-p.verified:
	case msg := <-p.failed:
		t.Fatalf("easyssf-java: %s", msg)
	case <-time.After(waitTimeout):
		t.Fatal("easyssf-java accepted no verification event")
	}
}

func (p *javaPeer) Next(t *testing.T) received {
	t.Helper()
	select {
	case r := <-p.got:
		return r
	case msg := <-p.failed:
		t.Fatalf("easyssf-java: %s", msg)
	case <-time.After(waitTimeout):
		t.Fatalf("easyssf-java handled no event within %s", waitTimeout)
	}
	return received{}
}

// push hands a pushed request to easyssf's push handler, and returns its
// response.
func (p *javaPeer) push(t *testing.T, authorization string, body []byte) (int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b64 := base64.StdEncoding
	if _, err := fmt.Fprintf(p.stdin, "push %s %s\n",
		b64.EncodeToString([]byte(authorization)), b64.EncodeToString(body)); err != nil {
		return http.StatusServiceUnavailable, ""
	}
	select {
	case l := <-p.pushed:
		return l.PushStatus, l.PushBody
	case <-time.After(waitTimeout):
		t.Error("easyssf-java answered no push")
		return http.StatusServiceUnavailable, ""
	}
}

func (p *javaPeer) send(t *testing.T, command string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := io.WriteString(p.stdin, command+"\n"); err != nil {
		t.Fatalf("writing to the Java program: %v", err)
	}
}

// transmitterRoot returns, as PEM, the root certificate the Transmitter's
// TLS chain verifies to under the client it hands out, for the Java
// program to trust.
func transmitterRoot(t *testing.T, tx *ssftest.Transmitter) []byte {
	t.Helper()
	tr, ok := tx.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("the Transmitter's client has no TLS configuration")
	}
	u, err := url.Parse(tx.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: u.Hostname()})
	if err != nil {
		t.Fatalf("connecting to the Transmitter: %v", err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().VerifiedChains[0]
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[len(chain)-1].Raw})
}
