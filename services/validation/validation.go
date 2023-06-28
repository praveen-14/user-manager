package validation

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/praveen-14/user-manager/services/logger"
	"github.com/praveen-14/user-manager/utils"
)

const (
	ErrInvalidEmail             = utils.ConstError("Email invalid")
	ErrNotASriLankanPhoneNumber = utils.ConstError("Not a Sri Lankan phone number")
)

var (
	instance *Service
	once     sync.Once
)

type Service struct {
	loggingService *logger.Service
}

func New() (*Service, error) {
	var err error
	once.Do(func() {
		instance = &Service{
			loggingService: logger.New("validation-service", 0),
		}
	})
	return instance, err
}

func (service *Service) ProcessString(str string) string {
	return strings.TrimSpace(str)
}

func (service *Service) ValidateEmail(email string) (_ string, err error) {
	_, err = mail.ParseAddress(email)
	if err != nil {
		service.loggingService.Print("INFO", "email validation failed email=%s", email)
		return "", ErrInvalidEmail
	}
	return service.ProcessString(email), nil
}

func (service *Service) ValidateSriLankanPhoneNumber(number string) (_ string, err error) {
	var re = regexp.MustCompile(`(?m)^(?:0|94|\+94)?(?:(11|21|23|24|25|26|27|31|32|33|34|35|36|37|38|41|45|47|51|52|54|55|57|63|65|66|67|81|912)(0|2|3|4|5|7|9)|7(0|1|2|4|5|6|7|8)\d)\d{6}`)
	number = service.ProcessString(number)
	if !re.MatchString(number) {
		service.loggingService.Print("INFO", "sri lankan number validation failed number=%s", number)
		return "", ErrNotASriLankanPhoneNumber
	}
	return number, nil
}

func (service *Service) ValidatePassword(s string) (err error) {
	var number, upper, special bool
	letters := 0
	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
			letters++
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		case unicode.IsLetter(c) || c == ' ':
			letters++
		}
	}
	minLetters := 7 // can be moved to config
	if letters < minLetters || !number || !upper || !special {
		return fmt.Errorf("password must contain at least %d letters, a special character, an uppercase letter and a number", minLetters)
	}
	return nil
}
