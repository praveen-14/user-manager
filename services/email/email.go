package email

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sync"

	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/utils"

	"github.com/praveen-14/user-manager/services/logger"

	"github.com/k3a/html2text"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

var (
	instance *Service
	once     sync.Once
)

type (
	Service struct {
		*template.Template

		loggingService *logger.Service
	}
)

func New() (*Service, error) {
	var err error
	once.Do(func() {
		instance = &Service{
			loggingService: logger.New("email-service", 0),
		}
		err = instance.ParseTemplateDir(config.EMAIL_TEMPLATE_DIR)
	})
	return instance, err
}

func (service *Service) ParseTemplateDir(dir string) error {
	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("path list = %s", paths))
	service.Template, err = template.ParseFiles(paths...)
	if err != nil {
		return err
	}
	return nil
}

func (service *Service) SendVerificationCode(token string, code string, email string, name string, redirectURL string) error {

	var body bytes.Buffer

	data := map[string]string{
		"URL":       fmt.Sprintf("%s?data=%s", redirectURL, token),
		"FirstName": name,
		"Message":   "Please verify your account to be able to login",
		"BtnText":   "Verify your account",
		"ORG_NAME":  config.ORG_NAME,
	}
	fmt.Println(data)

	err := service.Template.ExecuteTemplate(&body, "body.html", data)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to load body.html template. err = %s", err))
		return err
	}

	from := mail.NewEmail(config.FROM_NAME, config.FROM_EMAIL)
	subject := fmt.Sprintf("Your Verification Code for %s", config.ORG_NAME)

	to := mail.NewEmail(name, email)

	message := mail.NewSingleEmail(from, subject, to, html2text.HTML2Text(body.String()), body.String())

	client := sendgrid.NewSendClient(config.SENDGRID_API_KEY)
	response, err := client.Send(message)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to email verification code to %s. response %s", email, utils.String(response)))
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully emailed verification code to %s. response %+v", email, utils.String(response)))
	return nil
}

func (service *Service) SendPasswordResetCode(token string, email string, name string, redirectURL string) error {

	var body bytes.Buffer

	data := map[string]string{
		"URL":       fmt.Sprintf("%s?data=%s", redirectURL, token),
		"FirstName": name,
		"Message":   "Here's the link to reset your password",
		"BtnText":   "Reset Passowrd",
	}

	err := service.Template.ExecuteTemplate(&body, "body.html", data)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to load body.html template. err = %s", err))
		return err
	}

	from := mail.NewEmail(config.FROM_NAME, config.FROM_EMAIL)
	subject := fmt.Sprintf("Reset Your %s Password", config.ORG_NAME)

	to := mail.NewEmail(name, email)

	message := mail.NewSingleEmail(from, subject, to, html2text.HTML2Text(body.String()), body.String())

	client := sendgrid.NewSendClient(config.SENDGRID_API_KEY)
	response, err := client.Send(message)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to email password reset code to %s. response %s", email, utils.String(response)))
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully emailed password reset code to %s. response %+v", email, utils.String(response)))
	return nil
}
