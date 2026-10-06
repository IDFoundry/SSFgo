package receiver

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
)

// maxSETBytes bounds a pushed SET.
const maxSETBytes = 64 * 1024

// PushOptions configures PushHandler.
type PushOptions struct {
	// AuthorizationHeader, if set, is the exact Authorization header
	// value every push must carry — the value the Receiver gave the
	// Transmitter as delivery.authorization_header (SSF 1.0 §6.1.1).
	// Requests without it are refused with 401.
	AuthorizationHeader string
}

// PushHandler returns the http.Handler for a push delivery endpoint
// (RFC 8935). It answers 202 once a SET has been verified and handled
// (or recognised as a redelivery), 400 with an RFC 8935 error body for a
// SET it rejects, and 500 when a handler fails, so the Transmitter
// retries.
func (r *Receiver) PushHandler(opts PushOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.AuthorizationHeader != "" &&
			subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte(opts.AuthorizationHeader)) != 1 {
			pushError(w, http.StatusUnauthorized, errCodeAuthenticationFailed, "the Authorization header is missing or wrong")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxSETBytes))
		if err != nil {
			pushError(w, http.StatusBadRequest, setcodec.CodeInvalidRequest, "the request body could not be read")
			return
		}
		jti, err := r.processObserved(req.Context(), ssf.DeliveryPush, string(body))
		if rej, ok := isRejection(err); ok {
			r.cfg.Logger.WarnContext(req.Context(), "ssf receiver: rejected pushed SET", "jti", jti, "err", rej.code, "description", rej.description)
			pushError(w, http.StatusBadRequest, rej.code, rej.description)
			return
		}
		if err != nil {
			r.cfg.Logger.ErrorContext(req.Context(), "ssf receiver: handling pushed SET failed", "jti", jti, "error", err)
			http.Error(w, "the SET could not be processed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}

// pushError writes an RFC 8935 §2.3 error response.
func pushError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Content-Language", "en")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"err": code, "description": description})
}
