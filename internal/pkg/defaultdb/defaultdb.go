package defaultdb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
	"golang.org/x/crypto/openpgp"
)

const (
	keyPrefix = "keys:"
)

type entityRecord struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Fingerprint string `json:"fingerprint"`
	Key         []byte `json:"key"`
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
		"fingerprint": true,
		"name":        true,
		"email":       true,
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
		if err := b.db.CreateIndex(index, keyPrefix+"*", buntdb.IndexJSON(index)); err != nil {
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
		val, err := marshalEntityRecord(e)
		if err != nil {
			return err
		}
		fmt.Println(val)
		_, _, err = tx.Set(keyPrefix+e.PrimaryKey.KeyIdString(), val, nil)
		return err
	})
}

func (b *bunt) Get(s database.SearchPattern, options string, exact bool) (openpgp.EntityList, error) {
	var err error
	var el openpgp.EntityList

	search, err := url.PathUnescape(string(s))
	if err != nil {
		return nil, err
	}

	logrus.WithField("search", search).Info("Search key")

	if s.IsFingerprint() {
		// fingerprint search
		search = strings.ToUpper(strings.TrimPrefix(search, "0x"))

		fp, err := hex.DecodeString(search)
		if err != nil {
			return nil, err
		}

		fpKey := ""

		switch len(fp) {
		case 4:
		case 8:
			fpKey = fmt.Sprintf("%X", fp)
		case 20:
			fpKey = fmt.Sprintf("%X", fp[12:20])
		default:
			return nil, fmt.Errorf("fingerprint must be either 4, 8 or 20 bytes length")
		}

		err = b.db.View(func(tx *buntdb.Tx) error {
			if exact {
				val, err := tx.Get(keyPrefix + fpKey)
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

			if fpKey == "" {
				fpKey = fmt.Sprintf("%X", fp)
			}
			keyPattern := fmt.Sprintf("%s*%s", keyPrefix, fpKey)

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
	}

	return el, err
}

func marshalEntityRecord(e *openpgp.Entity) (string, error) {
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
	if err := e.Serialize(buf); err != nil {
		return "", err
	}

	er := entityRecord{
		Name:        identity.UserId.Name,
		Email:       identity.UserId.Email,
		Fingerprint: fmt.Sprintf("%X", e.PrimaryKey.Fingerprint[:]),
		Key:         buf.Bytes(),
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
	database.RegisterDatabase("", db)
}
