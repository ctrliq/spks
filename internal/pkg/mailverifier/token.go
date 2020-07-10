package mailverifier

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func (m *MailVerifier) generateToken(e *openpgp.Entity) (string, error) {
	// resulting hash of the serialized and encrypted public key
	token := md5.New()

	// for reproducible hash
	config := &packet.Config{
		Rand: bytes.NewReader(m.sessionKey[:]),
	}

	wc, err := openpgp.SymmetricallyEncrypt(token, m.passphrase[:], nil, config)
	if err != nil {
		return "", err
	}

	// serialize write public key to be ciphered and hashed
	if err := e.Serialize(wc); err != nil {
		wc.Close()
		return "", err
	}
	if err := wc.Close(); err != nil {
		return "", err
	}

	return hex.EncodeToString(token.Sum(nil)), nil
}
