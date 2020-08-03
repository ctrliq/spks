package hkpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctrl-cmd/spks/pkg/database"
	"github.com/ctrl-cmd/spks/pkg/keyring"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/time/rate"
)

const (
	DefaultAddr = "localhost:11371"
)

const (
	AddRoute    = "/pks/add"
	LookupRoute = "/pks/lookup"
)

type RateLimit string

func (r RateLimit) Parse() (int, int, error) {
	limit := string(r)
	if limit == "" {
		return 0, 0, nil
	}
	s := strings.Split(limit, "/")
	if len(s) != 2 {
		return -1, -1, fmt.Errorf("rate limit must be of the form 1/1 not %s", limit)
	}
	req, err := strconv.ParseInt(s[0], 10, 32)
	if err != nil {
		return -1, -1, fmt.Errorf("while parsing burst limit request: %s", err)
	}
	min, err := strconv.ParseInt(s[1], 10, 32)
	if err != nil {
		return -1, -1, fmt.Errorf("while parsing burst limit second: %s", err)
	}
	return int(req), int(min), nil
}

type Config struct {
	Addr             string
	PublicPem        string
	PrivatePem       string
	DB               database.DatabaseEngine
	Verifier         Verifier
	CustomHandler    func(http.Handler) http.Handler
	MaxHeaderBytes   int
	MaxBodyBytes     int64
	KeyPushRateLimit RateLimit
}

type userLimit struct {
	limiter *rate.Limiter
	last    time.Time
}

type hkpHandler struct {
	maxBodyBytes    int64
	db              database.DatabaseEngine
	verifier        Verifier
	usersLimit      map[string]*userLimit
	usersLimitMutex sync.Mutex
	rateRequests    int
	rateMinutes     int
}

func (h *hkpHandler) pushLimitReached(ip string) bool {
	// rate limit disabled
	if h.usersLimit == nil {
		return false
	}

	h.usersLimitMutex.Lock()
	defer h.usersLimitMutex.Unlock()

	u, ok := h.usersLimit[ip]
	if !ok {
		rt := rate.Every((time.Duration(h.rateMinutes) * time.Minute) / time.Duration(h.rateRequests))
		h.usersLimit[ip] = &userLimit{
			limiter: rate.NewLimiter(rt, 1),
			last:    time.Now(),
		}
		return false
	}

	u.last = time.Now()
	return !u.limiter.Allow()
}

// add provides the /pks/add HKP handler.
func (h *hkpHandler) add(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		NewMethodNotAllowedStatus().Write(w)
		return
	}

	if l, ok := w.(*logResponseWriter); ok {
		if h.pushLimitReached(l.ip) {
			NewTooManyRequestStatus().Write(w)
			return
		}
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
	var err error

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

	handler.rateRequests, handler.rateMinutes, err = cfg.KeyPushRateLimit.Parse()
	if err != nil {
		return err
	} else if handler.rateRequests > 0 && handler.rateMinutes > 0 {
		// rate limit enabled
		handler.usersLimit = make(map[string]*userLimit)
		ticker := time.NewTicker(1 * time.Minute)
		lifetime := time.Duration(handler.rateMinutes) * time.Minute
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					handler.usersLimitMutex.Lock()
					for ip, v := range handler.usersLimit {
						if time.Since(v.last) > lifetime {
							delete(handler.usersLimit, ip)
						}
					}
					handler.usersLimitMutex.Unlock()
				}
			}
		}()
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
