package defaultdb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/tidwall/buntdb"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	keySep       = ":"
	keyPrefix    = "key" + keySep
	sigKeyPrefix = "sigkey" + keySep
)

type entityRecord struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Key   []byte `json:"key"`
}

type Config struct {
	Dir string `yaml:"dir"`
}

type bunt struct {
	db  *buntdb.DB
	cfg Config
}

func (b *bunt) NewConfig() database.Config {
	return &b.cfg
}

func (b *bunt) Connect() error {
	var err error

	createIndexes := map[string]bool{
		keyPrefix + "name":     true,
		keyPrefix + "email":    true,
		sigKeyPrefix + "name":  true,
		sigKeyPrefix + "email": true,
	}

	if b.cfg.Dir == "" {
		b.db, err = buntdb.Open(":memory:")
	} else {
		b.db, err = buntdb.Open(filepath.Join(b.cfg.Dir, "db"))
	}
	if err != nil {
		return err
	}

	indexes, err := b.db.Indexes()
	if err != nil {
		return err
	}

	for _, index := range indexes {
		if _, ok := createIndexes[index]; ok {
			createIndexes[index] = false
		}
	}

	for index := range createIndexes {
		splitted := strings.Split(index, keySep)
		prefix := splitted[0]
		field := splitted[1]
		if err := b.db.CreateIndex(index, prefix+keySep+"*", buntdb.IndexJSON(field)); err != nil {
			return fmt.Errorf("could not create index %s: %s", index, err)
		}
	}

	return err
}

func (b *bunt) Disconnect() error {
	return b.db.Close()
}

func (b *bunt) Add(e *openpgp.Entity) error {
	return b.db.Update(func(tx *buntdb.Tx) error {
		fp := e.PrimaryKey.KeyIdString()
		val, err := marshalEntityRecord(e, false)
		if err != nil {
			return err
		}
		_, _, err = tx.Set(keyPrefix+fp, val, nil)
		if err != nil {
			return err
		}
		// key entity with a private part is a signing key
		if e.PrivateKey != nil {
			val, err := marshalEntityRecord(e, true)
			if err != nil {
				return err
			}
			_, _, err = tx.Set(sigKeyPrefix+fp, val, nil)
			if err != nil {
				return err
			}
		}
		return err
	})
}

func (b *bunt) Del(e *openpgp.Entity) error {
	return b.db.Update(func(tx *buntdb.Tx) error {
		fpKey := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint[12:20])
		if _, err := tx.Delete(sigKeyPrefix + fpKey); err != buntdb.ErrNotFound {
			return err
		}
		if _, err := tx.Delete(keyPrefix + fpKey); err != buntdb.ErrNotFound {
			return err
		}
		return nil
	})
}

func (b *bunt) Get(search string, isFingerprint bool, exact bool, kt database.KeyType) (openpgp.EntityList, error) {
	var err error
	var el openpgp.EntityList

	kp := keyPrefix
	if kt == database.SigningKey {
		kp = sigKeyPrefix
	}

	if isFingerprint {
		// fingerprint search
		fp, err := hex.DecodeString(search)
		if err != nil {
			return nil, err
		}

		fpKey := ""

		switch len(fp) {
		case 4, 8:
			fpKey = fmt.Sprintf("%X", fp)
		case 20:
			fpKey = fmt.Sprintf("%X", fp[12:20])
		default:
			return nil, fmt.Errorf("fingerprint must be either 4, 8 or 20 bytes length")
		}

		err = b.db.View(func(tx *buntdb.Tx) error {
			if exact {
				val, err := tx.Get(kp + fpKey)
				if err != nil {
					if err == buntdb.ErrNotFound {
						return nil
					}
					return err
				}
				e, err := unmarshalEntityRecord(val)
				if err != nil {
					return err
				}
				el = append(el, e)
				return nil
			}

			keyPattern := fmt.Sprintf("%s*%s", kp, fpKey)

			return tx.AscendKeys(keyPattern, func(key, val string) bool {
				e, err := unmarshalEntityRecord(val)
				if err != nil {
					return false
				}
				el = append(el, e)
				return true
			})
		})
	} else {
		// text search
		err = b.db.View(func(tx *buntdb.Tx) error {
			if exact {
				// first search for email
				err := tx.AscendEqual(kp+"email", search, func(key, val string) bool {
					e, err := unmarshalEntityRecord(val)
					if err != nil {
						return false
					}
					el = append(el, e)
					return false
				})
				if err != nil {
					return err
				}
				if len(el) == 1 {
					return nil
				}
				// search for name
				return tx.AscendEqual(kp+"name", search, func(key, val string) bool {
					e, err := unmarshalEntityRecord(val)
					if err != nil {
						return false
					}
					el = append(el, e)
					return false
				})
			}
			return tx.Ascend(kp+"email", func(key, val string) bool {
				r := gjson.GetMany(val, "name", "email")
				if len(r) != 2 {
					return true
				}
				name := r[0].String()
				email := r[1].String()

				if strings.Contains(name, search) || strings.Contains(email, search) {
					e, err := unmarshalEntityRecord(val)
					if err != nil {
						return true
					}
					el = append(el, e)
				}
				return true
			})
		})
	}

	return el, err
}

func marshalEntityRecord(e *openpgp.Entity, private bool) (string, error) {
	var identity *openpgp.Identity

	for _, id := range e.Identities {
		if id.SelfSignature.IsPrimaryId != nil && *id.SelfSignature.IsPrimaryId {
			identity = id
			break
		}
	}

	if identity == nil {
		return "", fmt.Errorf("no suitable identity found")
	}

	buf := new(bytes.Buffer)

	// if the entity has a private key, we know this key is the signing
	// key set and used by the server.
	if private {
		if err := e.SerializePrivate(buf, nil); err != nil {
			return "", err
		}
	} else {
		if err := e.Serialize(buf); err != nil {
			return "", err
		}
	}

	er := entityRecord{
		Name:  identity.UserId.Name,
		Email: identity.UserId.Email,
		Key:   buf.Bytes(),
	}

	b, err := json.Marshal(&er)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func unmarshalEntityRecord(val string) (*openpgp.Entity, error) {
	var e *openpgp.Entity
	var er entityRecord

	if err := json.Unmarshal([]byte(val), &er); err != nil {
		return nil, err
	}

	packets := packet.NewReader(bytes.NewReader(er.Key))
	e, err := openpgp.ReadEntity(packets)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return e, nil
}

func init() {
	db := new(bunt)
	database.RegisterDatabaseEngine("", db)
}
