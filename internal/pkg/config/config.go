package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ctrl-cmd/spks/internal/pkg/defaultdb"
	"github.com/ctrl-cmd/spks/internal/pkg/mailer"
	"github.com/ctrl-cmd/spks/pkg/database"
	"github.com/ctrl-cmd/spks/pkg/hkpserver"
	"gopkg.in/yaml.v3"
)

const (
	Dir  = "/etc/spks"
	File = "server.yaml"
)

type Certificate struct {
	PublicKeyPath  string `yaml:"public-key"`
	PrivateKeyPath string `yaml:"private-key"`
}

type ServerConfig struct {
	BindAddr  string `yaml:"bind-address"`
	PublicURL string `yaml:"public-url"`

	SigningPGPKey string `yaml:"signing-pgpkey"`

	Certificate Certificate `yaml:"certificate"`

	MailerConfig mailer.Config `yaml:"mail"`

	DBEngine string                 `yaml:"db"`
	DBConfig map[string]interface{} `yaml:"db-config"`
}

var DefaultServerConfig ServerConfig = ServerConfig{
	BindAddr:     hkpserver.DefaultAddr,
	PublicURL:    "http://" + hkpserver.DefaultAddr,
	MailerConfig: mailer.DefaultConfig,
	DBEngine:     defaultdb.Name,
}

func Parse(path string) (ServerConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return ServerConfig{}, err
	} else if os.IsNotExist(err) {
		return DefaultServerConfig, nil
	}

	srvConfig := ServerConfig{}
	if err := yaml.Unmarshal(b, &srvConfig); err != nil {
		return ServerConfig{}, err
	}

	if srvConfig.DBEngine == "" {
		srvConfig.DBEngine = defaultdb.Name
	}

	// parse the database configuration
	db, ok := database.GetDatabaseEngine(srvConfig.DBEngine)
	if !ok {
		return ServerConfig{}, fmt.Errorf("unknown database engine '%s'", srvConfig.DBEngine)
	}

	b, err = yaml.Marshal(srvConfig.DBConfig)
	if err != nil {
		return ServerConfig{}, err
	}
	if err := yaml.Unmarshal(b, db.NewConfig()); err != nil {
		return ServerConfig{}, err
	}

	return srvConfig, nil
}

func CheckServerConfig(cfg ServerConfig) error {
	if cfg.PublicURL == "" {
		return fmt.Errorf("configuration public-url is missing or empty")
	}
	if err := mailer.CheckConfig(&cfg.MailerConfig); err != nil {
		return err
	}
	return nil
}
