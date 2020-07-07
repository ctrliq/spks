package hkpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ctrl-cmd/pks/pkg/database"
	"golang.org/x/crypto/openpgp"
)

var (
	ErrNotPermitted = errors.New("Not permitted")
	ErrDuplicateKey = errors.New("Duplicated key")
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
	Addr       string
	PublicPem  string
	PrivatePem string
	DB         database.Database
	VerifyKey  VerifyKey
}

type defaultHandler struct {
	db        database.Database
	verifyKey VerifyKey
}

func (h *defaultHandler) add(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			http.Error(w, "Not implemented", http.StatusNotImplemented)
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
	fp := fmt.Sprintf("0x%X", e.PrimaryKey.Fingerprint[:])
	eldb, err := h.db.Get(database.SearchPattern(fp), "", true)

	// check duplicate
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if len(eldb) > 1 {
		http.Error(w, "BUGGED!!!!", http.StatusInternalServerError)
		return
	} else if len(eldb) == 1 {
		// check if this is a revocation signature
		for _, rsig := range e.Revocations {
			if err := eldb[0].PrimaryKey.VerifyRevocationSignature(rsig); err != nil {
				http.Error(w, "Not permitted", http.StatusForbidden)
				return
			}
		}
		// report conflict if this is not a revocation submission
		if len(e.Revocations) == 0 {
			http.Error(w, "Duplicated key", http.StatusConflict)
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

func (h *defaultHandler) lookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	options := ""
	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			options = "nm"
		}
	}

	search := query.Get("search")
	exact := query.Get("exact") == "on"

	switch query.Get("op") {
	case "get":
		el, err := h.db.Get(database.SearchPattern(search), options, exact)
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
		el, err := h.db.Get(database.SearchPattern(search), options, exact)
		if err != nil {
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
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	}
}

func Start(ctx context.Context, cfg Config) error {
	shutdownCh := make(chan error, 1)

	if cfg.DB == nil {
		return fmt.Errorf("no database specified")
	}

	mux := http.NewServeMux()
	handler := &defaultHandler{cfg.DB, cfg.VerifyKey}

	mux.HandleFunc(AddRoute, handler.add)
	mux.HandleFunc(LookupRoute, handler.lookup)

	addr := cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: logRequestHandler(mux),
	}

	if err := cfg.DB.Connect(); err != nil {
		return fmt.Errorf("while connecting to database: %s", err)
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

	err = <-shutdownCh

	cfg.DB.Disconnect()

	return err
}
