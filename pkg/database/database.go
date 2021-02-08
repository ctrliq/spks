// Copyright (c) 2020-2021, Ctrl IQ, Inc. All rights reserved
// SPDX-License-Identifier: BSD-3-Clause

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

var databaseEngines = make(map[string]Engine)

// RegisterDatabaseEngine registers a database engine.
func RegisterDatabaseEngine(name string, db Engine) {
	databaseEngines[name] = db
}

// GetDatabaseEngine returns the database engine correspo
func GetDatabaseEngine(name string) (Engine, bool) {
	db, ok := databaseEngines[name]
	return db, ok
}

// Engine defines interface that database engines must implement.
type Engine interface {
	// NewConfig returns a config instance for the corresponding DB engine.
	NewConfig() Config
	// CheckConfig ensure proper configuration parameters and also handle
	// configuration set by environment variables.
	CheckConfig() error

	// Connect initiates connection to the database.
	Connect() error
	// Disconnect initiates disconnection from the database.
	Disconnect() error

	// Add adds the provided keys into the database.
	Add(e openpgp.EntityList) error
	// Del removes the provided keys from the database.
	Del(e openpgp.EntityList) error
	// Get retrieves keys corresponding to the search pattern.
	Get(s string, isFingerprint bool, exact bool, kt KeyType) (openpgp.EntityList, error)
}
