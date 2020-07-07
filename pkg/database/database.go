package database

import (
	"strings"

	"golang.org/x/crypto/openpgp"
)

type Config interface{}

var databases = make(map[string]Database)

func RegisterDatabase(name string, db Database) {
	databases[name] = db
}

func GetDatabase(name string) (Database, bool) {
	db, ok := databases[name]
	return db, ok
}

type SearchPattern string

func (s SearchPattern) String() string {
	return string(s)
}

func (s SearchPattern) IsFingerprint() bool {
	return strings.HasPrefix(string(s), "0x")
}

type Database interface {
	NewConfig() Config

	Connect() error
	Disconnect() error

	Add(e *openpgp.Entity) error
	Get(s SearchPattern, options string, exact bool) (openpgp.EntityList, error)
}
