package hkpserver

import (
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type printEntity struct {
	entity  *openpgp.Entity
	selfSig *packet.Signature
}

func newPrintEntity(e *openpgp.Entity) *printEntity {
	pe := &printEntity{entity: e}

	for _, id := range pe.entity.Identities {
		if id.SelfSignature.IsPrimaryId != nil && *id.SelfSignature.IsPrimaryId {
			pe.selfSig = id.SelfSignature
			break
		}
		pe.selfSig = id.SelfSignature
	}

	return pe
}

func (pe *printEntity) print(w io.Writer) error {
	key := pe.entity.PrimaryKey

	bitLength, err := key.BitLength()
	if err != nil {
		return err
	}

	ct := uint64(key.CreationTime.Unix())
	et := uint64(0)
	if pe.selfSig.KeyLifetimeSecs != nil {
		et = ct + uint64(*pe.selfSig.KeyLifetimeSecs)
	}
	expiration := ""
	if et != 0 {
		expiration = fmt.Sprint(et)
	}

	flags := ""
	if pe.selfSig.SigExpired(time.Now()) {
		flags += "e"
	}
	if len(pe.entity.Revocations) > 0 {
		flags += "r"
	}

	_, err = fmt.Fprintf(
		w,
		"pub:%X:%d:%d:%d:%s:%s\n",
		key.Fingerprint[:], key.PubKeyAlgo, bitLength, ct, expiration, flags,
	)
	if err != nil {
		return err
	}

	for _, id := range pe.entity.Identities {
		if id.SelfSignature == nil {
			continue
		}

		ct := uint64(id.SelfSignature.CreationTime.Unix())
		et := uint64(0)
		if id.SelfSignature.KeyLifetimeSecs != nil {
			et = ct + uint64(*id.SelfSignature.KeyLifetimeSecs)
		}
		expiration := ""
		if et != 0 {
			expiration = fmt.Sprint(et)
		}

		flags := ""
		if id.SelfSignature.SigExpired(time.Now()) {
			flags += "e"
		}
		if id.SelfSignature.RevocationReason != nil {
			flags += "r"
		}

		_, err := fmt.Fprintf(
			w,
			"uid:%s:%d:%s:%s\n",
			strings.ReplaceAll(id.Name, ":", "%3A"), ct, expiration, flags,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteIndex writes on w a readable index based on the entity list
// provided. The index format follows the one described in the HKP draft
// https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-5.2
func WriteIndex(w io.Writer, el openpgp.EntityList) error {
	_, err := fmt.Fprintf(w, "info:1:%d\n", len(el))
	if err != nil {
		return err
	}

	for _, e := range el {
		pe := newPrintEntity(e)
		if err := pe.print(w); err != nil {
			return err
		}
	}

	return nil
}
