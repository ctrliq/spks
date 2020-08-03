package hkpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctrl-cmd/spks/internal/pkg/defaultdb"
	"github.com/ctrl-cmd/spks/pkg/database"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/time/rate"
)

func TestStart(t *testing.T) {
	cfg := Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cfg.DB, _ = database.GetDatabaseEngine(defaultdb.Name)
	if cfg.DB == nil {
		t.Fatalf("no default database found")
	}

	if err := Start(ctx, cfg); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func getEntities(t *testing.T, n int) openpgp.EntityList {
	el := make(openpgp.EntityList, n)

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("Test%d", i)
		mail := fmt.Sprintf("test%d@example.com", i)
		e, err := openpgp.NewEntity(name, "No comment", mail, nil)
		if err != nil {
			t.Fatalf("unexpected error while generating pgp key: %s", err)
		}
		el[i] = e
	}

	return el
}

func getArmored(t *testing.T, e *openpgp.Entity, private bool) string {
	b := new(bytes.Buffer)

	aw, err := armor.Encode(b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("during armor encoding: %s", err)
	}

	if e != nil {
		if private {
			if err := e.SerializePrivateWithoutSigning(aw, nil); err != nil {
				t.Fatalf("while serializing private key: %s", err)
			}
		} else {
			if err := e.Serialize(aw); err != nil {
				t.Fatalf("while serializing key: %s", err)
			}
		}
	}

	aw.Close()

	return b.String()
}

func TestHandler(t *testing.T) {
	// http handler
	handler := new(hkpHandler)
	handler.maxBodyBytes = int64(1 << 18)

	// setup test database
	handler.db, _ = database.GetDatabaseEngine(defaultdb.Name)
	if handler.db == nil {
		t.Fatalf("no default database found")
	}
	_ = handler.db.NewConfig().(*defaultdb.Config)
	if err := handler.db.Connect(); err != nil {
		t.Fatalf("unexpected error while connecting to database: %s", err)
	}
	defer handler.db.Disconnect()

	// generate two test keys
	testKeys := 2
	el := getEntities(t, testKeys)
	if len(el) != 2 {
		t.Fatalf("unexpected number of pgp key generated: got %d instead of %d", len(el), testKeys)
	}

	keyOne := el[0]
	keyOneArmored := getArmored(t, keyOne, false)
	kvOne := url.Values{}
	kvOne.Set("keytext", keyOneArmored)

	keyTwo := el[1]
	keyTwoArmored := getArmored(t, keyTwo, false)
	kvTwo := url.Values{}
	kvTwo.Set("keytext", keyTwoArmored)

	// for private key submission
	kvOnePrivate := url.Values{}
	kvOnePrivate.Set("keytext", getArmored(t, keyOne, true))

	// for empty key submission
	kvEmpty := url.Values{}
	kvEmpty.Set("keytext", getArmored(t, nil, false))

	tests := []struct {
		name     string
		method   string
		path     string
		handler  func(http.ResponseWriter, *http.Request)
		verifier Verifier
		body     io.Reader
		code     int
		content  string
	}{
		{
			name:    "post lookup",
			method:  "POST",
			path:    "/pks/lookup",
			code:    http.StatusMethodNotAllowed,
			handler: handler.lookup,
		},
		{
			name:    "nm option",
			method:  "GET",
			path:    "/pks/lookup?options=nm",
			code:    http.StatusNotImplemented,
			handler: handler.lookup,
		},
		{
			name:    "search without op",
			method:  "GET",
			path:    "/pks/lookup?search=test",
			code:    http.StatusNotImplemented,
			handler: handler.lookup,
		},
		{
			name:    "bad search",
			method:  "GET",
			path:    "/pks/lookup?search=%25GG",
			code:    http.StatusBadRequest,
			content: "Bad search parameter",
			handler: handler.lookup,
		},
		{
			name:    "too short fingerprint search",
			method:  "GET",
			path:    "/pks/lookup?search=0x0000&op=get",
			code:    http.StatusBadRequest,
			content: "Fingerprint search must have at least 8 characters",
			handler: handler.lookup,
		},
		{
			name:    "get null short fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x00000000&op=get",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "index null short fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x00000000&op=index",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "get null long fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x0000000000000000&op=get",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "get null long fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x0000000000000000&op=index",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "get null full fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x0000000000000000000000000000000000000000&op=get",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "index null full fingerprint",
			method:  "GET",
			path:    "/pks/lookup?search=0x0000000000000000000000000000000000000000&op=index",
			code:    http.StatusNotFound,
			handler: handler.lookup,
		},
		{
			name:    "bad add method",
			method:  "GET",
			path:    "/pks/add",
			code:    http.StatusMethodNotAllowed,
			handler: handler.add,
		},
		{
			name:    "empty add",
			method:  "POST",
			path:    "/pks/add",
			code:    http.StatusInternalServerError,
			handler: handler.add,
		},
		{
			name:    "add nm option",
			method:  "POST",
			path:    "/pks/add?options=nm",
			code:    http.StatusNotImplemented,
			handler: handler.add,
		},
		{
			name:    "add no key database",
			method:  "POST",
			path:    "/pks/add",
			code:    http.StatusBadRequest,
			body:    strings.NewReader(kvEmpty.Encode()),
			handler: handler.add,
		},
		{
			name:     "add key one with broken verifier",
			method:   "POST",
			path:     "/pks/add",
			code:     http.StatusInternalServerError,
			body:     strings.NewReader(kvOne.Encode()),
			verifier: &brokenVerifier{},
			handler:  handler.add,
		},
		{
			name:     "add key one with conflict verifier",
			method:   "POST",
			path:     "/pks/add",
			code:     http.StatusConflict,
			body:     strings.NewReader(kvOne.Encode()),
			verifier: &conflictVerifier{},
			handler:  handler.add,
		},
		{
			name:    "add key one database",
			method:  "POST",
			path:    "/pks/add",
			code:    http.StatusOK,
			body:    strings.NewReader(kvOne.Encode()),
			handler: handler.add,
		},
		{
			name:     "add key one database with ok verifier",
			method:   "POST",
			path:     "/pks/add",
			code:     http.StatusOK,
			body:     strings.NewReader(kvOne.Encode()),
			verifier: &okVerifier{},
			handler:  handler.add,
		},
		{
			name:    "add private key one database",
			method:  "POST",
			path:    "/pks/add",
			code:    http.StatusBadRequest,
			body:    strings.NewReader(kvOnePrivate.Encode()),
			handler: handler.add,
		},
		{
			name:    "add key two database",
			method:  "POST",
			path:    "/pks/add",
			code:    http.StatusOK,
			body:    strings.NewReader(kvTwo.Encode()),
			handler: handler.add,
		},
		{
			name:    "get key one database long fingerprint",
			method:  "GET",
			path:    "/pks/lookup?op=get&search=0x" + keyOne.PrimaryKey.KeyIdString(),
			code:    http.StatusOK,
			content: keyOneArmored,
			handler: handler.lookup,
		},
		{
			name:    "get key two database long fingerprint",
			method:  "GET",
			path:    "/pks/lookup?op=get&search=0x" + keyTwo.PrimaryKey.KeyIdString(),
			code:    http.StatusOK,
			content: keyTwoArmored,
			handler: handler.lookup,
		},
		{
			name:    "get database long exact fingerprint",
			method:  "GET",
			path:    "/pks/lookup?op=get&exact=on&search=0x" + keyOne.PrimaryKey.KeyIdString(),
			code:    http.StatusOK,
			handler: handler.lookup,
		},
		{
			name:    "get database long fingerprint",
			method:  "GET",
			path:    "/pks/lookup?op=index&search=0x" + keyOne.PrimaryKey.KeyIdString(),
			code:    http.StatusOK,
			handler: handler.lookup,
		},
	}

	for _, tt := range tests {
		resp := httptest.NewRecorder()
		target := "http://localhost" + tt.path
		req := httptest.NewRequest(tt.method, target, tt.body)

		if tt.method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		if tt.handler == nil {
			t.Errorf("no handler set for %q", tt.name)
			continue
		}

		handler.verifier = tt.verifier

		tt.handler(resp, req)

		if resp.Code != tt.code {
			t.Errorf("unexpected http status returned for %q: got %d instead of %d", tt.name, resp.Code, tt.code)
		} else if tt.content != "" {
			ct := resp.Header().Get("Content-Type")
			if ct == "application/json" {
				var er ErrorResponse
				if err := json.Unmarshal(resp.Body.Bytes(), &er); err != nil {
					t.Errorf("unexpected error while unmarshalling json error response: %s", err)
				} else if er.Error.Message != tt.content {
					t.Errorf("unexpected content returned for %q: got %s instead of %s", tt.name, er.Error.Message, tt.content)
				}
				continue
			}
			if tt.content != resp.Body.String() {
				t.Errorf("unexpected content returned for %q: got %s instead of %s", tt.name, resp.Body.String(), tt.content)
			}
		}
	}
}

func TestRateLimit(t *testing.T) {
	// http handler
	handler := new(hkpHandler)
	handler.maxBodyBytes = int64(1 << 18)
	handler.usersLimit = make(map[string]*rate.Limiter)
	handler.rateMinutes = 1
	handler.rateRequests = 2

	tests := []struct {
		name         string
		limitReached bool
	}{
		{
			name:         "First request OK",
			limitReached: false,
		},
		{
			name:         "Second request OK",
			limitReached: false,
		},
		{
			name:         "Third request KO",
			limitReached: true,
		},
	}

	first := true
restart:

	for _, tt := range tests {
		lr := handler.pushLimitReached("127.0.0.1")
		if lr != tt.limitReached {
			t.Errorf("unexpected result from pushLimitReached: got %v instead of %v", lr, tt.limitReached)
		}
	}

	if first {
		// re-run tests after 1 minute to check if the rate limit
		// has been reset correctly
		time.Sleep(1 * time.Minute)
		first = false
		goto restart
	}
}
