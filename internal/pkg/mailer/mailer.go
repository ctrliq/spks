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
	SMTPServer:      "localhost",
	SMTPPort:        25,
	Sender:          "admin@ctrl-cmd.com",
	AllowedDomains:  []string{"ctrl-cmd.com"},
	Subject:         DefaultSubject,
	MessageTemplate: DefaultTemplate,
}

const (
	mailSMTPServerEnv     = "SPKS_MAIL_SMTP_SERVER"
	mailSMTPPortEnv       = "SPKS_MAIL_SMTP_PORT"
	mailSenderEnv         = "SPKS_MAIL_SENDER"
	mailSMTPUsernameEnv   = "SPKS_MAIL_SMTP_USERNAME"
	mailSMTPPasswordEnv   = "SPKS_MAIL_SMTP_PASSWORD"
	mailSMTPInsecureEnv   = "SPKS_MAIL_SMTP_INSECURE_TLS"
	mailAllowedDomainsEnv = "SPKS_MAIL_ALLOWED_DOMAINS"
)

type Config struct {
	SMTPServer      string   `yaml:"smtp-server"`
	SMTPPort        int      `yaml:"smtp-port"`
	SMTPInsecureTLS bool     `yaml:"smtp-insecure-tls"`
	SMTPUsername    string   `yaml:"smtp-username"`
	SMTPPassword    string   `yaml:"smtp-password"`
	Sender          string   `yaml:"sender"`
	Subject         string   `yaml:"subject"`
	MessageTemplate string   `yaml:"message"`
	AllowedDomains  []string `yaml:"allowed-domains"`
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
	env := os.Getenv(mailSMTPServerEnv)
	if env != "" {
		cfg.SMTPServer = env
	}
	env = os.Getenv(mailSMTPPortEnv)
	if env != "" {
		b, err := strconv.ParseUint(env, 10, 16)
		if err != nil {
			return fmt.Errorf("while parsing %s: %s", mailSMTPPortEnv, err)
		}
		cfg.SMTPPort = int(b)
	}
	env = os.Getenv(mailSenderEnv)
	if env != "" {
		cfg.Sender = env
	}
	env = os.Getenv(mailSMTPUsernameEnv)
	if env != "" {
		cfg.SMTPUsername = env
	}
	env = os.Getenv(mailSMTPPasswordEnv)
	if env != "" {
		cfg.SMTPPassword = env
	}
	env = os.Getenv(mailSMTPInsecureEnv)
	if env != "" {
		b, err := strconv.ParseBool(env)
		if err != nil {
			return fmt.Errorf("while parsing %s: %s", mailSMTPInsecureEnv, err)
		}
		cfg.SMTPInsecureTLS = b
	}
	env = os.Getenv(mailAllowedDomainsEnv)
	if env != "" {
		cfg.AllowedDomains = strings.Split(env, ",")
		for i, d := range cfg.AllowedDomains {
			cfg.AllowedDomains[i] = strings.TrimSpace(d)
		}
	}

	if cfg.SMTPServer == "" {
		return fmt.Errorf("smtp server address within mail configuration is missing or empty")
	}
	if cfg.Sender == "" {
		return fmt.Errorf("sender address within mail configuration is missing or empty")
	}
	return nil
}

func Send(cfg *Config, m ...*gomail.Message) error {
	port := cfg.SMTPPort
	host := cfg.SMTPServer

	if port == 0 {
		port = 587
	}
	if host == "" {
		return fmt.Errorf("a SMTP host server must be specified")
	}

	d := gomail.NewDialer(host, port, cfg.SMTPUsername, cfg.SMTPPassword)
	if (port == 587 || port == 465) && cfg.SMTPInsecureTLS {
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
