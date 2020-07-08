package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/openpgp/packet"

	// load the default database engine
	_ "github.com/ctrl-cmd/pks/internal/pkg/defaultdb"

	"github.com/ctrl-cmd/pks/internal/pkg/config"
	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/ctrl-cmd/pks/pkg/hkpserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
)

func addSigningKey(el openpgp.EntityList, db database.DatabaseEngine) error {
	if len(el) != 1 {
		return fmt.Errorf("found %d signing pgp key(s), only one can be set", len(el))
	}

	e := el[0]
	if e.PrivateKey == nil {
		return fmt.Errorf("signing key requires private key")
	} else if e.PrivateKey.Encrypted {
		return fmt.Errorf("private key is encrypted")
	}

	return db.Add(e)
}

func execute() error {
	cfg, err := config.Parse(filepath.Join(config.Dir, config.File))
	if err != nil {
		return fmt.Errorf("while parsing configuration file: %s", err)
	}

	db, ok := database.GetDatabaseEngine(cfg.DBEngine)
	if !ok {
		return fmt.Errorf("no database engine %s", cfg.DBEngine)
	}
	scfg := hkpserver.Config{
		Addr:          cfg.BindAddr,
		PublicPem:     cfg.Certificate.PublicKeyPath,
		PrivatePem:    cfg.Certificate.PrivateKeyPath,
		DB:            db,
		CustomHandler: hkpserver.LogRequestHandler,
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

	generateSigningKey := true

	if cfg.SigningPGPKey != "" {
		if _, err := os.Stat(cfg.SigningPGPKey); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("while getting signing pgp key: %s", err)
		} else if err == nil {
			generateSigningKey = false

			logrus.WithField("path", cfg.SigningPGPKey).Info("Using signing PGP key")
			b, err := ioutil.ReadFile(cfg.SigningPGPKey)
			if err != nil {
				return fmt.Errorf("while reading signing pgp key: %s", err)
			}
			el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
			if err != nil {
				return fmt.Errorf("while decoding signing pgp key: %s", err)
			}
			if err := addSigningKey(el, db); err != nil {
				return err
			}
		}
	}

	if generateSigningKey {
		logrus.Info("Generating signing PGP key")

		conf := &packet.Config{RSABits: 4096, DefaultHash: crypto.SHA384}
		e, err := openpgp.NewEntity("Admin", "Signing Key", cfg.SMTP.Email, conf)
		if err != nil {
			return fmt.Errorf("while generating signing pgp key: %s", err)
		}
		logrus.WithField("fingerprint", e.PrimaryKey.KeyIdString()).Info("Signing PGP key generated")

		if err := addSigningKey(openpgp.EntityList{e}, db); err != nil {
			return err
		}
	}

	logrus.WithField("listen", cfg.BindAddr).Info("Server started")

	return hkpserver.Start(ctx, scfg)
}

func main() {
	if err := execute(); err != nil {
		logrus.WithError(err).Fatal("while running server")
	}
}
