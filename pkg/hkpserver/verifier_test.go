package hkpserver

import (
	"net/http"

	"github.com/ctrliq/spks/pkg/database"
	"golang.org/x/crypto/openpgp"
)

type brokenVerifier struct{}

func (brokenVerifier) Init(database.Engine, *http.ServeMux) error {
	return nil
}

func (brokenVerifier) Verify(openpgp.EntityList, *http.Request) (openpgp.EntityList, Status) {
	return nil, nil
}

type conflictVerifier struct{}

func (conflictVerifier) Init(database.Engine, *http.ServeMux) error {
	return nil
}

func (conflictVerifier) Verify(openpgp.EntityList, *http.Request) (openpgp.EntityList, Status) {
	return nil, NewConflictStatus()
}

type okVerifier struct{}

func (okVerifier) Init(database.Engine, *http.ServeMux) error {
	return nil
}

func (okVerifier) Verify(el openpgp.EntityList, _ *http.Request) (openpgp.EntityList, Status) {
	return el, NewOKStatus()
}
