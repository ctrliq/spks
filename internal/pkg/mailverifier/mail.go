package mailverifier

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/ctrl-cmd/spks/internal/pkg/config"
	"github.com/ctrl-cmd/spks/internal/pkg/mailer"
	"github.com/ctrl-cmd/spks/pkg/database"
	"github.com/ctrl-cmd/spks/pkg/hkpserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
)

var _ hkpserver.Verifier = &MailVerifier{}

type MailVerifier struct {
	config     *config.ServerConfig
	processing []processingFunc
	db         database.DatabaseEngine
	signingKey *openpgp.Entity
	passphrase [64]byte
	sessionKey [64]byte
}

func New(config *config.ServerConfig, signingKey *openpgp.Entity) *MailVerifier {
	v := &MailVerifier{
		config:     config,
		signingKey: signingKey,
	}
	v.processing = []processingFunc{
		v.checkSingleIdentity,  // ensure keys have only one identity
		v.checkRevocation,      // accept key revocation without validation
		v.checkDuplicateKey,    // fail if a key exist with the same fingerprint
		v.checkValidSubmission, // validation process via basic auth token
		v.checkEmail,           // check if mail address in key identity is whitelisted
	}
	if config.MailIdentityVerification {
		v.processing = append(v.processing, v.sendEmail)
	} else {
		v.processing = append(v.processing, v.noEmail)
	}
	return v
}

func (m *MailVerifier) Init(db database.DatabaseEngine, _ *http.ServeMux) error {
	m.db = db
	_, err := io.ReadFull(rand.Reader, m.sessionKey[:])
	if err != nil {
		return err
	}
	_, err = io.ReadFull(rand.Reader, m.passphrase[:])
	return err
}

func (m *MailVerifier) Verify(el openpgp.EntityList, r *http.Request) (openpgp.EntityList, hkpserver.Status) {
	// for simplicity only one key submission is supported
	if len(el) > 1 {
		return nil, hkpserver.NewBadRequestStatus("Only one key submission is supported")
	} else if len(el) == 0 {
		return nil, hkpserver.NewBadRequestStatus("A key must be provided")
	}

	e := el[0]

	var dbEntity *openpgp.Entity

	fp := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint[:])
	eldb, err := m.db.Get(fp, true, true, database.PublicKey)
	if err != nil {
		return nil, hkpserver.NewInternalServerErrorStatus("Database access failed")
	} else if len(eldb) > 1 {
		return nil, hkpserver.NewInternalServerErrorStatus("Multiple keys found for fingerprint " + fp)
	} else if len(eldb) == 1 {
		dbEntity = eldb[0]
	}

	for _, check := range m.processing {
		if status := check(e, dbEntity, r); status != nil {
			if status.IsError() {
				return nil, status
			} else if status.Is(http.StatusAccepted) {
				// accepted status here means that the key
				// requires a validation before being added
				logrus.WithField("fingerprint", fp).Info("Key accepted")
				return nil, status
			}
			return el, status
		}
	}

	logrus.Error("Mail verification failed")
	// processing failed meaning something is broken
	return nil, hkpserver.NewInternalServerErrorStatus("Mail verification failed")
}

func (m *MailVerifier) sendEmail(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	var id *openpgp.Identity
	for key := range e.Identities {
		id = e.Identities[key]
		break
	}

	// process auth token
	token, err := m.generateToken(e)
	if err != nil {
		return hkpserver.NewInternalServerErrorStatus("Token generation failed")
	}

	u, err := url.Parse(m.config.PublicURL)
	if err != nil {
		return hkpserver.NewInternalServerErrorStatus("Bad server configuration")
	}
	u.User = url.User(token)

	from := m.config.AdminEmail
	to := id.UserId.Email
	args := &mailer.TemplateArgs{
		Name:          id.UserId.Name,
		PublicURL:     m.config.PublicURL,
		PublicAuthURL: u.String(),
		Fingerprint:   fmt.Sprintf("%X", e.PrimaryKey.Fingerprint[12:20]),
	}

	templateMsg := m.config.MailerConfig.MessageTemplate
	if templateMsg == "" {
		templateMsg = mailer.DefaultTemplate
	}
	subject := m.config.MailerConfig.Subject
	if subject == "" {
		subject = mailer.DefaultSubject
	}

	tmpl, err := template.New("message").Parse(templateMsg)
	if err != nil {
		return hkpserver.NewInternalServerErrorStatus("Mail message parsing failed")
	}
	s := new(strings.Builder)
	err = tmpl.Execute(s, args)
	if err != nil {
		return hkpserver.NewInternalServerErrorStatus("Mail message processing failed")
	}

	logrus.WithField("to", to).Info("Sending public key")

	msg := mailer.NewMessage(from, to, subject, s.String())

	if err := mailer.Send(&m.config.MailerConfig, msg); err != nil {
		return hkpserver.NewInternalServerErrorStatus(err.Error())
	}

	return hkpserver.NewAcceptedStatus("Key accepted, validation instructions sent to", to)
}

func (m *MailVerifier) noEmail(e *openpgp.Entity, dbe *openpgp.Entity, r *http.Request) hkpserver.Status {
	return hkpserver.NewOKStatus()
}
