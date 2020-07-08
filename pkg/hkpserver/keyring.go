package hkpserver

import (
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// WriteArmoredKeyRing writes the armored ASCII format of the
// entity list to w.
func WriteArmoredKeyRing(w io.Writer, el openpgp.EntityList) error {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer aw.Close()

	for _, e := range el {
		if err := e.Serialize(aw); err != nil {
			return err
		}
	}

	return nil
}
