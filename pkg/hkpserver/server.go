package hkpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctrl-cmd/pks/pkg/database"
	"golang.org/x/crypto/openpgp"
)

var (
	ErrNotPermitted     = errors.New("Not permitted")
	ErrBadRequest       = errors.New("Bad request")
	ErrMethodNotAllowed = errors.New("Method not allowed")
	ErrNotImplemented   = errors.New("Not implemented")
	ErrDuplicateKey     = errors.New("Duplicated key")
)

const (
	DefaultAddr = ":11371"
)

const (
	AddRoute    = "/pks/add"
	LookupRoute = "/pks/lookup"
)

type VerifyKey func(*openpgp.Entity) (bool, error)

type Config struct {
	Addr          string
	PublicPem     string
	PrivatePem    string
	DB            database.DatabaseEngine
	VerifyKey     VerifyKey
	CustomHandler func(http.Handler) http.Handler
}

type hkpHandler struct {
	db        database.DatabaseEngine
	verifyKey VerifyKey
}

// add provides the /pks/add HKP handler.
func (h *hkpHandler) add(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrMethodNotAllowed.Error(), http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			http.Error(w, ErrNotImplemented.Error(), http.StatusNotImplemented)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := strings.NewReader(r.PostForm.Get("keytext"))
	el, err := openpgp.ReadArmoredKeyRing(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// for simplicity only one key submission is supported
	if len(el) > 1 {
		http.Error(w, "Only one key submission is supported", http.StatusBadRequest)
		return
	} else if len(el) == 0 {
		http.Error(w, "A key must be provided", http.StatusBadRequest)
		return
	}

	e := el[0]
	// prevents private keys from being stored, this also
	// helps database engine to distinguish key added
	// internally (server signing key) or from this handler
	if e.PrivateKey != nil {
		http.Error(w, "Keys submitted must not contain private key", http.StatusBadRequest)
		return
	}

	fp := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint[:])
	eldb, err := h.db.Get(fp, true, true, database.PublicKey)

	// check duplicate
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if len(eldb) > 1 {
		http.Error(w, "BUGGED!!!!", http.StatusInternalServerError)
		return
	} else if len(eldb) == 1 {
		// report conflict if this is not a revocation submission
		if len(e.Revocations) == 0 {
			http.Error(w, ErrDuplicateKey.Error(), http.StatusConflict)
			return
		}
		// revoked key, updating database
		if err := h.db.Add(e); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}

	// first see, go through validation process if any
	if h.verifyKey != nil {
		verified, err := h.verifyKey(e)
		if err != nil {
			errMsg := err.Error()
			status := http.StatusInternalServerError
			switch err {
			case ErrNotPermitted:
				status = http.StatusForbidden
			case ErrDuplicateKey:
				status = http.StatusConflict
			}
			http.Error(w, errMsg, status)
			return
		} else if !verified {
			// if there is no error reported and the
			// key wasn't flagged as verified we return
			// an accepted status meaning the key has been
			// processed for further verification (eg: mail)
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}

	if err := h.db.Add(e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// lookup provides the /pks/lookup HKP handler.
func (h *hkpHandler) lookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, ErrMethodNotAllowed.Error(), http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			http.Error(w, ErrNotImplemented.Error(), http.StatusNotImplemented)
			return
		}
	}

	exact := query.Get("exact") == "on"

	search, err := url.QueryUnescape(query.Get("search"))
	if err != nil {
		http.Error(w, "A key must be provided", http.StatusBadRequest)
		return
	}

	isFingerprint := strings.HasPrefix(search, "0x")
	if isFingerprint {
		search = strings.TrimPrefix(search, "0x")
		search = strings.ToUpper(search)
		length := len(search)
		if length < 8 {
			http.Error(w, ErrBadRequest.Error(), http.StatusBadRequest)
			return
		} else if length < 16 {
			search = search[length-8:]
		} else if length < 40 {
			search = search[length-16:]
		}
	}

	switch query.Get("op") {
	case "get":
		el, err := h.db.Get(search, isFingerprint, exact, database.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if len(el) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		if err := WriteArmoredKeyRing(w, el); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "index", "vindex":
		el, err := h.db.Get(search, isFingerprint, exact, database.PublicKey)
		if err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if len(el) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := WriteIndex(w, el); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	default:
		http.Error(w, ErrNotImplemented.Error(), http.StatusNotImplemented)
	}
}

// Start starts HKP server with the corresponding server configuration.
func Start(ctx context.Context, cfg Config) error {
	shutdownCh := make(chan error, 1)

	if cfg.DB == nil {
		return fmt.Errorf("no database specified")
	}

	mux := http.NewServeMux()
	handler := &hkpHandler{cfg.DB, cfg.VerifyKey}

	mux.HandleFunc(AddRoute, handler.add)
	mux.HandleFunc(LookupRoute, handler.lookup)

	addr := cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}

	srv := &http.Server{
		Addr: addr,
	}
	if cfg.CustomHandler != nil {
		srv.Handler = cfg.CustomHandler(mux)
	}

	go func() {
		select {
		case <-ctx.Done():
			shutdownCh <- srv.Shutdown(context.Background())
		}
	}()

	var err error

	if cfg.PublicPem != "" && cfg.PrivatePem != "" {
		err = srv.ListenAndServeTLS(cfg.PublicPem, cfg.PrivatePem)
	} else {
		err = srv.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		return err
	}

	return <-shutdownCh
}
