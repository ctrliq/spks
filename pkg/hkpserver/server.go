package hkpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/ctrl-cmd/pks/pkg/keyring"
	"golang.org/x/crypto/openpgp"
)

const (
	DefaultAddr = ":11371"
)

const (
	AddRoute    = "/pks/add"
	LookupRoute = "/pks/lookup"
)

type Config struct {
	Addr           string
	PublicPem      string
	PrivatePem     string
	DB             database.DatabaseEngine
	Verifier       Verifier
	CustomHandler  func(http.Handler) http.Handler
	MaxHeaderBytes int
	MaxBodyBytes   int64
}

type hkpHandler struct {
	maxBodyBytes int64
	db           database.DatabaseEngine
	verifier     Verifier
}

// add provides the /pks/add HKP handler.
func (h *hkpHandler) add(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		NewMethodNotAllowedStatus().Write(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	query := r.URL.Query()

	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			NewNotImplementedStatus().Write(w)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		NewInternalServerErrorStatus(err.Error()).Write(w)
		return
	}

	s := strings.NewReader(r.PostForm.Get("keytext"))
	el, err := openpgp.ReadArmoredKeyRing(s)
	if err != nil {
		NewInternalServerErrorStatus(err.Error()).Write(w)
		return
	} else if len(el) == 0 {
		NewBadRequestStatus("No key submitted").Write(w)
		return
	}

	// prevents private keys from being stored, this also
	// helps database engine to distinguish key added
	// internally (server signing key) or from this handler
	for _, e := range el {
		if e.PrivateKey != nil {
			NewBadRequestStatus("Keys submitted must not contain private key").Write(w)
			return
		}
	}

	var keys openpgp.EntityList
	var status Status

	// go through validation process if any
	if h.verifier != nil {
		keys, status = h.verifier.Verify(el, r)
		if status == nil {
			NewInternalServerErrorStatus("Broken verifier").Write(w)
			return
		}
		if len(keys) == 0 || status.IsError() {
			status.Write(w)
			return
		}
	} else {
		keys = el
	}

	if status == nil {
		status = NewOKStatus("Key(s) submitted successfully")
	}

	if err := h.db.Add(keys); err != nil {
		NewInternalServerErrorStatus(err.Error()).Write(w)
		return
	}

	status.Write(w)
}

// lookup provides the /pks/lookup HKP handler.
func (h *hkpHandler) lookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		NewMethodNotAllowedStatus().Write(w)
		return
	}

	query := r.URL.Query()

	for _, opt := range strings.Split(query.Get("options"), ",") {
		switch strings.TrimSpace(opt) {
		case "nm":
			NewNotImplementedStatus().Write(w)
			return
		}
	}

	exact := query.Get("exact") == "on"

	search, err := url.QueryUnescape(query.Get("search"))
	if err != nil {
		NewBadRequestStatus("Bad search parameter").Write(w)
		return
	}

	isFingerprint := strings.HasPrefix(search, "0x")
	if isFingerprint {
		search = strings.TrimPrefix(search, "0x")
		search = strings.ToUpper(search)
		length := len(search)
		if length < 8 {
			NewBadRequestStatus("Fingerprint search must have at least 8 characters").Write(w)
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
			NewInternalServerErrorStatus(err.Error()).Write(w)
			return
		} else if len(el) == 0 {
			NewNotFoundStatus().Write(w)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		if err := keyring.WriteArmoredKeyRing(w, el); err != nil {
			NewInternalServerErrorStatus(err.Error()).Write(w)
			return
		}
	case "index", "vindex":
		el, err := h.db.Get(search, isFingerprint, exact, database.PublicKey)
		if err != nil {
			NewInternalServerErrorStatus(err.Error()).Write(w)
			return
		} else if len(el) == 0 {
			NewNotFoundStatus().Write(w)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := WriteIndex(w, el); err != nil {
			NewInternalServerErrorStatus(err.Error()).Write(w)
			return
		}
	default:
		NewNotImplementedStatus().Write(w)
		return
	}
}

// Start starts HKP server with the corresponding server configuration.
func Start(ctx context.Context, cfg Config) error {
	shutdownCh := make(chan error, 1)

	if cfg.DB == nil {
		return fmt.Errorf("no database specified")
	}

	maxBodyBytes := int64(1 << 18) // limit body size to 64K by default
	if cfg.MaxBodyBytes != 0 {
		maxBodyBytes = cfg.MaxBodyBytes
	}

	mux := http.NewServeMux()
	handler := &hkpHandler{
		maxBodyBytes: maxBodyBytes,
		db:           cfg.DB,
		verifier:     cfg.Verifier,
	}

	mux.HandleFunc(AddRoute, handler.add)
	mux.HandleFunc(LookupRoute, handler.lookup)

	if cfg.Verifier != nil {
		// Init can panic if the verifier registers one of the
		// http route above, as this is considered as a developer
		// mistake and break the Verify interface, just warn here
		// and let developer fixing it
		if err := cfg.Verifier.Init(cfg.DB, mux); err != nil {
			return fmt.Errorf("while initializing verifier: %s", err)
		}
	}

	addr := cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}

	maxHeaderBytes := 1 << 12 // limit header size to 4K by default
	if cfg.MaxHeaderBytes != 0 {
		maxHeaderBytes = cfg.MaxHeaderBytes
	}

	srv := &http.Server{
		Addr:           addr,
		MaxHeaderBytes: maxHeaderBytes,
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
