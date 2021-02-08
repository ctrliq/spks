// Copyright (c) 2020-2021, Ctrl IQ, Inc. All rights reserved
// SPDX-License-Identifier: BSD-3-Clause

package hkpserver

import (
	"net/http"

	"github.com/ctrliq/spks/pkg/database"
	"golang.org/x/crypto/openpgp"
)

// Verifier is the key verifier interface allowing
// HKP to reject/accept keys based on custom criteria.
type Verifier interface {
	Init(database.Engine, *http.ServeMux) error
	Verify(openpgp.EntityList, *http.Request) (openpgp.EntityList, Status)
}
