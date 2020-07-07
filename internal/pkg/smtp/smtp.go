package smtp

import (
	"crypto/tls"
	"fmt"

	"gopkg.in/gomail.v2"
)

var DefaultSMTPConfig Config = Config{
	Host: "localhost",
	Port: 25,
}

type Config struct {
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	Email          string   `yaml:"email"`
	User           string   `yaml:"user"`
	Password       string   `yaml:"password"`
	InsecureTLS    bool     `yaml:"insecure-tls"`
	AllowedDomains []string `yaml:"allowed-domains"`
}

func SendMail(cfg *Config, m ...*gomail.Message) error {
	port := cfg.Port
	host := cfg.Host

	if port == 0 {
		port = 587
	}
	if host == "" {
		return fmt.Errorf("a SMTP host server must be specified")
	}

	d := gomail.NewDialer(host, port, cfg.User, cfg.Password)
	if (port == 587 || port == 465) && cfg.InsecureTLS {
		d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return d.DialAndSend(m...)
}
