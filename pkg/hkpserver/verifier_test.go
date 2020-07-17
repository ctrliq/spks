package hkpserver

import (
	"net/http"

	"github.com/ctrl-cmd/spks/pkg/database"
	"golang.org/x/crypto/openpgp"
)

type brokenVerifier struct{}

func (brokenVerifier) Init(database.DatabaseEngine, *http.ServeMux) error {
	return nil
}

func (brokenVerifier) Verify(openpgp.EntityList, *http.Request) (openpgp.EntityList, Status) {
	return nil, nil
}

type conflictVerifier struct{}

func (conflictVerifier) Init(database.DatabaseEngine, *http.ServeMux) error {
	return nil
}

func (conflictVerifier) Verify(openpgp.EntityList, *http.Request) (openpgp.EntityList, Status) {
	return nil, NewConflictStatus()
}

type okVerifier struct{}

func (okVerifier) Init(database.DatabaseEngine, *http.ServeMux) error {
	return nil
}

func (okVerifier) Verify(el openpgp.EntityList, _ *http.Request) (openpgp.EntityList, Status) {
	return el, NewOKStatus()
}
