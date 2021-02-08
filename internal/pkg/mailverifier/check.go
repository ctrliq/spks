// Copyright (c) 2020-2021, Ctrl IQ, Inc. All rights reserved
// SPDX-License-Identifier: BSD-3-Clause

package mailverifier

import (
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/ctrliq/spks/pkg/database"
	"github.com/ctrliq/spks/pkg/hkpserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
)

// processingFunc represents functions doing basic check on PGP key,
// it take two arguments, the first argument represents the PGP key
// being submitted and the second argument represents the PGP key
// found in the database if any and associated by fingerprint match
// to the submitted PGP key.
type processingFunc func(*openpgp.Entity, *openpgp.Entity, *http.Request) hkpserver.Status

// checkRevocation accepts revoked key.
func (m *MailVerifier) checkRevocation(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	if len(e.Revocations) > 0 && dbe != nil {
		logrus.WithField("fingerprint", e.PrimaryKey.KeyIdString()).Info("Revoked key submitted")
		// from openpgp package if we are here, the key revocation
		// signature has been verified and therefore can be trusted
		return hkpserver.NewOKStatus("Revoked key submitted successfully")
	}
	return nil
}

// checkSingleIdentity checks that key has only one identity.
func (m *MailVerifier) checkSingleIdentity(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	if len(e.Identities) != 1 {
		logrus.WithField("fingerprint", e.PrimaryKey.KeyIdString()).Info("Key rejected, more than one identity")
		return hkpserver.NewBadRequestStatus("Key rejected, more than one identity")
	}
	return nil
}

// checkEmail checks that key has an identity with a valid email
// address and that the domain is allowed. Also ensures there is
// no other keys in the database with the same email address.
func (m *MailVerifier) checkEmail(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	var id *openpgp.Identity
	isPrimary := false

	for key := range e.Identities {
		id = e.Identities[key]
		if id.SelfSignature != nil && id.SelfSignature.IsPrimaryId != nil {
			isPrimary = *id.SelfSignature.IsPrimaryId
		}
		break
	}

	if !isPrimary {
		return hkpserver.NewBadRequestStatus(fmt.Sprintf("%q is not the primary identity", id.Name))
	}

	email, err := mail.ParseAddress(id.UserId.Email)
	if err != nil {
		return hkpserver.NewBadRequestStatus("Key rejected, invalid email address")
	}

	for _, domain := range m.config.MailIdentityDomains {
		if strings.HasSuffix(email.Address, domain) {
			el, err := m.db.Get(email.Address, false, true, database.PublicKey)
			if err != nil {
				return hkpserver.NewInternalServerErrorStatus("Database error")
			} else if len(el) > 0 {
				if len(el[0].Revocations) == 0 {
					return hkpserver.NewConflictStatus("Key rejected, duplicated key identity")
				}
			}
			return nil
		}
	}

	if len(m.config.MailIdentityDomains) > 0 {
		return hkpserver.NewBadRequestStatus("Key rejected, invalid email domain")
	}
	return nil
}

// checkValidSubmission checks that the key was submitted with credentials given
// in the sent email.
func (m *MailVerifier) checkValidSubmission(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	token, _, ok := r.BasicAuth()
	if !ok {
		return nil
	}

	origToken, err := m.generateToken(e)
	if err != nil {
		return hkpserver.NewInternalServerErrorStatus("Token generation error")
	} else if token != origToken {
		return nil
	}

	for key := range e.Identities {
		// sign identity
		if err := e.SignIdentity(key, m.signingKey, nil); err != nil {
			return hkpserver.NewInternalServerErrorStatus("Signing error")
		}
		break
	}

	return hkpserver.NewOKStatus("Key validated and signed")
}

func (m *MailVerifier) checkDuplicateKey(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	if dbe != nil {
		return hkpserver.NewConflictStatus("Duplicate key")
	}
	return nil
}
