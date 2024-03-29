// Copyright (c) 2020-2021, Ctrl IQ, Inc. All rights reserved
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ctrliq/spks/internal/pkg/config"
	"github.com/ctrliq/spks/internal/pkg/mailverifier"
	"github.com/ctrliq/spks/pkg/database"
	"github.com/ctrliq/spks/pkg/hkpserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// set by mage at build time
var version string

func addSigningKey(el openpgp.EntityList, db database.Engine) error {
	if len(el) != 1 {
		return fmt.Errorf("found %d signing pgp key(s), only one can be set", len(el))
	}

	e := el[0]
	if e.PrivateKey == nil {
		return fmt.Errorf("signing key requires private key")
	} else if e.PrivateKey.Encrypted {
		return fmt.Errorf("private key is encrypted")
	}

	return db.Add(el)
}

func execute(args []string) error {
	configPath := filepath.Join(config.Dir, config.File)
	if len(args) > 0 {
		configPath = args[0]
	}

	cfg, err := config.Parse(configPath)
	if err != nil {
		return fmt.Errorf("while parsing configuration file: %s", err)
	}

	if err := config.CheckServerConfig(&cfg); err != nil {
		return fmt.Errorf("while checking configuration: %s", err)
	}

	db, ok := database.GetDatabaseEngine(cfg.DBEngine)
	if !ok {
		return fmt.Errorf("no database engine %s", cfg.DBEngine)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := <-c
		logrus.WithField("signal", s).Info("Server interrupted by signal")
		cancel()
	}()

	if err := db.Connect(); err != nil {
		return fmt.Errorf("while connecting to database: %s", err)
	}
	defer db.Disconnect()

	var signingKey *openpgp.Entity

	// check if there is a signing key in the database
	eldb, err := db.Get("", true, false, database.SigningKey)
	if err != nil {
		return fmt.Errorf("while searching for signing key in database: %s", err)
	}
	for _, e := range eldb {
		if len(eldb[0].Revocations) == 0 {
			signingKey = e
			break
		}
	}

	if cfg.SigningPGPKey != "" && signingKey == nil {
		// look first if the signing key is provided as a base64 encoded string
		b, err := base64.StdEncoding.DecodeString(cfg.SigningPGPKey)
		if err != nil {
			b, err = ioutil.ReadFile(cfg.SigningPGPKey)
			if err != nil {
				return fmt.Errorf("while reading signing pgp key: %s", err)
			}
		}
		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("while decoding signing pgp key: %s", err)
		} else if len(el) == 0 {
			return fmt.Errorf("no signing key found")
		}
		logrus.WithField("identity", el[0].PrimaryIdentity().Name).Info("Using signing PGP key")
		if err := addSigningKey(el, db); err != nil {
			return err
		}
		signingKey = el[0]
	}

	if signingKey == nil {
		logrus.Info("Generating signing PGP key")

		conf := &packet.Config{RSABits: 4096, DefaultHash: crypto.SHA384}
		e, err := openpgp.NewEntity("Admin", "Signing Key", cfg.AdminEmail, conf)
		if err != nil {
			return fmt.Errorf("while generating signing pgp key: %s", err)
		}
		logrus.WithField("fingerprint", e.PrimaryKey.KeyIdString()).Info("Signing PGP key generated")

		if err := addSigningKey(openpgp.EntityList{e}, db); err != nil {
			return err
		}
		signingKey = e
	}

	scfg := hkpserver.Config{
		Addr:             cfg.BindAddr,
		PublicPem:        cfg.Certificate.PublicKeyPath,
		PrivatePem:       cfg.Certificate.PrivateKeyPath,
		DB:               db,
		CustomHandler:    hkpserver.LogRequestHandler,
		Verifier:         mailverifier.New(&cfg, signingKey),
		KeyPushRateLimit: cfg.KeyPushRateLimit,
	}

	logrus.WithField("listen", cfg.BindAddr).Infof("Server started (version %s)", version)

	return hkpserver.Start(ctx, scfg)
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		logrus.WithError(err).Fatal("while running server")
	}
}
