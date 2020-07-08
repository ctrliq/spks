package database

import (
	"golang.org/x/crypto/openpgp"
)

// KeyType defines the type of key to be stored in the database.
type KeyType uint8

const (
	// PublicKey is the key type for getting a public keys.
	PublicKey KeyType = iota
	// SigningKey is the key type used internally by the HKP server to
	// sign submitted user public keys.
	SigningKey
)

// Config is a generic config type for database used essentially during
// YAML configuration parsing, so database engines are free to implement
// their own configuration requirements.
type Config interface{}

var databaseEngines = make(map[string]DatabaseEngine)

// RegisterDatabaseEngine registers a database engine.
func RegisterDatabaseEngine(name string, db DatabaseEngine) {
	databaseEngines[name] = db
}

// GetDatabaseEngine returns the database engine correspo
func GetDatabaseEngine(name string) (DatabaseEngine, bool) {
	db, ok := databaseEngines[name]
	return db, ok
}

// DatabaseEngine defines interface that database engines must implement.
type DatabaseEngine interface {
	// NewConfig returns a config instance for the corresponding DB engine.
	NewConfig() Config

	// Connect initiates connection to the database.
	Connect() error
	// Disconnect initiates disconnection from the database.
	Disconnect() error

	// Add adds the provided key into the database.
	Add(e *openpgp.Entity) error
	// Del removes the provided key from the database.
	Del(e *openpgp.Entity) error
	// Get retrieves keys corresponding to the search pattern.
	Get(s string, isFingerprint bool, exact bool, kt KeyType) (openpgp.EntityList, error)
}
