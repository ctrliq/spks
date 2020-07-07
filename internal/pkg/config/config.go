package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ctrl-cmd/pks/internal/pkg/smtp"
	"github.com/ctrl-cmd/pks/pkg/database"
	"github.com/ctrl-cmd/pks/pkg/hkpserver"
	"gopkg.in/yaml.v3"
)

const (
	Dir  = "/etc/pks"
	File = "server.yaml"
)

type Certificate struct {
	PublicKeyPath  string `yaml:"public-key"`
	PrivateKeyPath string `yaml:"private-key"`
}

type ServerConfig struct {
	BindAddr string `yaml:"bind-address"`
	AdvURL   string `yaml:"advertise-url"`

	Certificate Certificate `yaml:"certificate"`

	SMTP smtp.Config `yaml:"smtp"`

	DB       string          `yaml:"db"`
	DBConfig database.Config `yaml:"db-config"`
}

var DefaultServerConfig ServerConfig = ServerConfig{
	BindAddr: hkpserver.DefaultAddr,
	AdvURL:   "http://" + hkpserver.DefaultAddr,
	SMTP:     smtp.DefaultSMTPConfig,
}

func (c *ServerConfig) UnmarshalYAML(value *yaml.Node) error {
	var dbConfigNode *yaml.Node
	dbName := ""

	for i, n := range value.Content {
		if n.Value == "db-config" {
			dbConfigNode = value.Content[i+1]
		} else if n.Value == "db" {
			dbName = value.Content[i+1].Value
		}
	}

	if dbConfigNode != nil && dbName != "" {
		db, ok := database.GetDatabase(dbName)
		if !ok {
			return fmt.Errorf("unknown database")
		}
		c.DBConfig = db.NewConfig()
		if c.DBConfig != nil {
			if err := dbConfigNode.Decode(c.DBConfig); err != nil {
				return err
			}
		}
	}

	return nil
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
	return srvConfig, nil
}
