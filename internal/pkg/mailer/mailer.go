package mailer

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/gomail.v2"
)

var DefaultConfig Config = Config{
	Host:            "localhost",
	Port:            25,
	Email:           "admin@ctrl-cmd.com",
	AllowedDomains:  []string{"ctrl-cmd.com"},
	Subject:         DefaultSubject,
	MessageTemplate: DefaultTemplate,
}

const (
	mailHostEnv        = "SPKS_MAIL_HOSTNAME"
	mailPortEnv        = "SPKS_MAIL_PORT"
	mailAddress        = "SPKS_MAIL_ADDRESS"
	mailUsername       = "SPKS_MAIL_USERNAME"
	mailPassword       = "SPKS_MAIL_PASSWORD"
	mailInsecure       = "SPKS_MAIL_INSECURE_TLS"
	mailAllowedDomains = "SPKS_MAIL_ALLOWED_DOMAINS"
)

type Config struct {
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	Email           string   `yaml:"email"`
	User            string   `yaml:"user"`
	Password        string   `yaml:"password"`
	InsecureTLS     bool     `yaml:"insecure-tls"`
	AllowedDomains  []string `yaml:"allowed-domains"`
	Subject         string   `yaml:"subject"`
	MessageTemplate string   `yaml:"message"`
}

type TemplateArgs struct {
	Name          string
	PublicURL     string
	PublicAuthURL string
	Fingerprint   string
}

var DefaultSubject = "Public key validation"

var DefaultTemplate = `Hello {{.Name}},

You've just submitted a public key on {{.PublicURL}}, this requires you to validate
that the key was pushed by you, so in order to finalize the validation process you
need to enter one of the following command from the same machine you originally pushed
the key:

- if you pushed it with Singularity please enter the following command in your terminal:

singularity key push -u {{.PublicAuthURL}} {{.Fingerprint}}

- if you pushed it with gpg tool, please enter the following command in your terminal:

curl --data-urlencode "keytext=$(gpg --armor --export {{.Fingerprint}})" {{.PublicAuthURL}}/pks/add

---------------------
This message was sent from the public key server {{.PublicURL}}.

Please ignore this message if you didn't submit this key or report any abuse by responding to this message.
`

func CheckConfig(cfg *Config) error {
	env := os.Getenv(mailHostEnv)
	if env != "" {
		cfg.Host = env
	}
	env = os.Getenv(mailPortEnv)
	if env != "" {
		b, err := strconv.ParseUint(env, 10, 16)
		if err != nil {
			return fmt.Errorf("while parsing %s: %s", mailPortEnv, err)
		}
		cfg.Port = int(b)
	}
	env = os.Getenv(mailAddress)
	if env != "" {
		cfg.Email = env
	}
	env = os.Getenv(mailUsername)
	if env != "" {
		cfg.User = env
	}
	env = os.Getenv(mailPassword)
	if env != "" {
		cfg.Password = env
	}
	env = os.Getenv(mailInsecure)
	if env != "" {
		b, err := strconv.ParseBool(env)
		if err != nil {
			return fmt.Errorf("while parsing %s: %s", mailInsecure, err)
		}
		cfg.InsecureTLS = b
	}
	env = os.Getenv(mailAllowedDomains)
	if env != "" {
		cfg.AllowedDomains = strings.Split(env, ",")
		for i, d := range cfg.AllowedDomains {
			cfg.AllowedDomains[i] = strings.TrimSpace(d)
		}
	}

	if cfg.Host == "" {
		return fmt.Errorf("host address withing mail configuration is missing or empty")
	}
	if cfg.Email == "" {
		return fmt.Errorf("email address within mail configuration is missing or empty")
	}
	return nil
}

func Send(cfg *Config, m ...*gomail.Message) error {
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

func NewMessage(from, to, subject, text string) *gomail.Message {
	m := gomail.NewMessage()

	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", text)

	return m
}
