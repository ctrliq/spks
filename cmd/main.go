package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	// load the default database engine
	_ "github.com/ctrl-cmd/pks/internal/pkg/defaultdb"

	"github.com/ctrl-cmd/pks/internal/pkg/config"
	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/ctrl-cmd/pks/pkg/hkpserver"
	"github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.Parse(filepath.Join(config.Dir, config.File))
	if err != nil {
		logrus.WithError(err).Fatal("while parsing configuration file")
	}

	db, ok := database.GetDatabase(cfg.DB)
	if !ok {
		logrus.Fatalf("No database engine %s", cfg.DB)
	}
	scfg := hkpserver.Config{
		Addr:       cfg.BindAddr,
		PublicPem:  cfg.Certificate.PublicKeyPath,
		PrivatePem: cfg.Certificate.PrivateKeyPath,
		DB:         db,
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := <-c
		logrus.WithField("signal", s).Info("Server interrupted by signal")
		cancel()
	}()

	logrus.WithField("listen", cfg.BindAddr).Info("Server started")

	if err := hkpserver.Start(ctx, scfg); err != nil {
		logrus.WithError(err).Fatal("while starting server")
	}
}
