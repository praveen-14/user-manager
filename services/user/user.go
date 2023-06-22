package user

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	"github.com/praveen-14/user-manager/services/email"
	"github.com/praveen-14/user-manager/services/logger"
	"github.com/praveen-14/user-manager/services/token"
	"github.com/praveen-14/user-manager/utils"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	// register errors
	ErrPasswordDoesNotMatch = utils.ConstError("Password does not match")

	ErrIncorrectPassword          = utils.ConstError("Incorrect password")
	ErrUserExists                 = utils.ConstError("User exists")
	ErrUserDoesNotExist           = utils.ConstError("User does not exist")
	ErrIncorrectValidationCode    = utils.ConstError("Incorrect validation code")
	ErrIncorrectPasswordResetCode = utils.ConstError("Incorrect password reset code")
	ErrPasswordResetNotRequested  = utils.ConstError("Password reset not requested")
	ErrUserRoleCannotBeEmpty      = utils.ConstError("Password reset not requested")
)

var (
	instance *Service
	once     sync.Once
)

type Service struct {
	db database.Database

	loggingService *logger.Service
	emailService   *email.Service
}

func New(db database.Database) (*Service, error) {
	var err error
	once.Do(func() {
		emailService, err1 := email.New()
		err = err1
		instance = &Service{
			loggingService: logger.New("user-service", 0),
			emailService:   emailService,
			db:             db,
		}
	})
	return instance, err
}

func (service *Service) AuthorizeUser(req AuthorizeUserRequest) (err error) {

	// check if user role is in allowed roles list
	roleAllowed := false
	for _, r := range req.AllowedRoles {
		if r == *req.User.Role {
			roleAllowed = true
			break
		}
	}
	if !roleAllowed {
		err = fmt.Errorf("role not allowed [user role = %s] [allowed roles = %+v]", *req.User.Role, req.AllowedRoles)
		return err
	}

	return nil
}

func (service *Service) AuthorizeToken(req AuthorizeTokenRequest) (user models.User, err error) {

	// check if token is valid
	claims := &AuthClaims{}
	err = token.ValidateToken(req.Token, claims)
	if err != nil {
		errStr := fmt.Sprintf("token validation failed, %s", err)
		service.loggingService.Print("FAIL", errStr)
		return user, err
	}

	// check if user exists
	user, err = service.GetUser(GetUserRequest{UserID: claims.UserID})
	if err != nil {
		service.loggingService.Print("FAIL", "failed to get user [REQ=%+v] [ERR=%s]", req, err)
		return user, err
	}

	// check if the token is the most recently issued token for this user
	if *user.Token != req.Token {
		err = fmt.Errorf("this token is no longer valid. A new token has been issued. please use that new token [provided token = %s]", req.Token)
		return user, err
	}

	err = service.AuthorizeUser(AuthorizeUserRequest{User: user, AllowedRoles: req.AllowedRoles})
	if err != nil {
		return user, err
	}

	return user, nil
}

func (service *Service) GetUser(req GetUserRequest) (user models.User, err error) {
	user, err = service.db.GetUser(req.UserID)
	if err != nil {
		if err == database.ErrNotFound {
			service.loggingService.Print("FAIL", fmt.Sprintf("user not found. [ID=%s]", req.UserID))
			return user, ErrUserDoesNotExist
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("failed to get user from database. [ID=%s] [Err=%s]", req.UserID, err))
			return user, err
		}
	}
	return user, nil
}

func (service *Service) GetUserByEmail(req GetUserByEmailRequest) (user models.User, err error) {
	user, err = service.db.GetUserByEmail(req.Email)
	if err != nil {
		if err == database.ErrNotFound {
			service.loggingService.Print("FAIL", fmt.Sprintf("user not found. [Email=%s]", req.Email))
			return user, ErrUserDoesNotExist
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("failed to get user from database. [Email=%s] [Err=%s]", req.Email, err))
			return user, err
		}
	}
	return user, nil
}

func (service *Service) GetUsers(req GetUsersRequest) (data <-chan *models.User, err error) {
	users, err := service.db.GetUsers(req.UserIDs)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to get users from database. [IDs=%+v] [Err=%s]", req.UserIDs, err))
		return data, err
	}
	return users, nil
}

func (service *Service) RegisterUser(req RegisterRequest) (err error) {

	if req.Password != req.PasswordConfirm {
		return ErrPasswordDoesNotMatch
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to hash password [Email=%s]", req.Email))
		return err
	}

	now := time.Now()
	verificationCodeSource := fmt.Sprint(rand.Int())
	verificationCode := verificationCodeSource[len(verificationCodeSource)-6:]
	id, _ := uuid.NewV4()
	email := strings.ToLower(req.Email)

	tokenStr, err := token.GenerateToken(&VerifyClaims{
		UserID:           id.String(),
		VerificationCode: verificationCode,
	})
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to generate jwt token [Email=%s] [Err=%s]", req.Email, err))
		return err
	}

	user := models.User{
		ID:                    utils.ToPointer(id.String()),
		Email:                 utils.ToPointer(email),
		Role:                  utils.ToPointer(req.Role),
		Name:                  utils.ToPointer(strings.ToLower(req.Name)),
		EmailVerified:         utils.ToPointer(false),
		MobileNumber:          utils.ToPointer(req.MobileNumber),
		CreatedAt:             utils.ToPointer(now.UnixMilli()),
		UpdatedAt:             utils.ToPointer(now.UnixMilli()),
		Deleted:               utils.ToPointer(false),
		Password:              utils.ToPointer(string(hashedPassword)),
		EmailVerificationCode: utils.ToPointer(verificationCode),
		Tags:                  utils.ToPointer([]string{}),
		Data:                  utils.ToPointer(req.Data),
	}

	err = service.emailService.SendVerificationCode(tokenStr, *user.EmailVerificationCode, *user.Email, *user.Name, req.RedirectURL)
	if err != nil {
		// if this fails, user added in previous step should be removed. Ideally this step should not fail if the email address user have given is correct
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to email verification code [Email=%s]", *user.Email))
		return err
	}

	err = service.db.AddUser(user)
	if err != nil {
		if err == database.ErrConflict {
			service.loggingService.Print("FAIL", fmt.Sprintf("user already exists [Email=%s]", *user.Email))
			return ErrUserExists
		}
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("user registration successful [Email=%s]", *user.Email))

	return nil

}

func (service *Service) LoginUser(req LoginRequest) (res *LoginResponse, err error) {

	user, err := service.GetUserByEmail(GetUserByEmailRequest{Email: req.Email})
	if err != nil {
		if err == database.ErrNotFound {
			service.loggingService.Print("FAIL", fmt.Sprintf("user not registered. [Email=%s]", req.Email))
			return nil, ErrUserDoesNotExist
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("failed to get user from database. [Email=%s] [Err=%s]", req.Email, err))
			return nil, err
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(req.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			service.loggingService.Print("INFO", fmt.Sprintf("password does not match. [Email=%s]", req.Email))
			return nil, ErrIncorrectPassword
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("password verification failed [Email=%s] [Err=%s]", req.Email, err))
			return nil, err
		}
	}

	now := time.Now()

	tokenStr, err := token.GenerateToken(&AuthClaims{
		UserID:    *user.ID,
		UserEmail: *user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * time.Duration(config.JWT_TOKEN_LIFESPAN_IN_MINUTES))),
		},
	})
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to generate jwt token [Email=%s] [Err=%s]", req.Email, err))
		return nil, err
	}

	userUpdates := models.User{ID: user.ID}
	userUpdates.LastLoggedInAt = utils.ToPointer(now.UnixMilli())
	userUpdates.Token = utils.ToPointer(tokenStr)

	err = service.db.UpdateUser(userUpdates, []string{}, []string{})
	if err != nil {
		return nil, err
	}

	res = &LoginResponse{
		Token: tokenStr,
		Name:  *user.Name,
	}

	return res, nil

}

func (service *Service) VerifyEmail(req VerifyRequest) (err error) {

	claims := &VerifyClaims{}
	err = token.ValidateToken(req.Data, claims)

	if err != nil {
		errStr := fmt.Sprintf("invalid data, %s", req.Data)
		service.loggingService.Print("FAIL", errStr)
		return fmt.Errorf(errStr)
	}

	user, err := service.GetUser(GetUserRequest{UserID: claims.UserID})
	if err != nil {
		service.loggingService.Print("FAIL", "user does not exist [Email=%s]", *user.Email)
		return err
	}

	if *user.EmailVerificationCode != claims.VerificationCode {
		service.loggingService.Print("FAIL", "codes does not match %s vs %s", *user.EmailVerificationCode, claims.VerificationCode)
		return ErrIncorrectValidationCode
	}

	now := time.Now()
	userUpdates := models.User{ID: user.ID}
	userUpdates.EmailVerified = utils.ToPointer(true)
	userUpdates.UpdatedAt = utils.ToPointer(now.UnixMilli())

	err = service.db.UpdateUser(userUpdates, []string{}, []string{})
	if err != nil {
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully verified %s", *user.ID))
	return nil
}

func (service *Service) ForgotPassword(req ForgotPasswordRequest) error {
	user, err := service.GetUserByEmail(GetUserByEmailRequest{Email: req.Email})
	if err != nil {
		if err == database.ErrNotFound {
			service.loggingService.Print("FAIL", fmt.Sprintf("user not registered. [Email=%s]", req.Email))
			return ErrUserDoesNotExist
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("failed to get user from database. [Email=%s] [Err=%s]", req.Email, err))
			return err
		}
	}

	now := time.Now()
	uuid, _ := uuid.NewV4()

	tokenStr, err := token.GenerateToken(&ResetPasswordClaims{
		Email:             *user.Email,
		PasswordResetCode: uuid.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * time.Duration(config.JWT_TOKEN_LIFESPAN_IN_MINUTES))),
		},
	})
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to generate jwt token [Email=%s] [Err=%s]", req.Email, err))
		return err
	}

	userUpdates := models.User{ID: user.ID}
	userUpdates.PasswordResetCode = utils.ToPointer(uuid.String())
	userUpdates.UpdatedAt = utils.ToPointer(now.UnixMilli())
	userUpdates.PasswordResetRequested = utils.ToPointer(true)

	err = service.db.UpdateUser(userUpdates, []string{}, []string{})
	if err != nil {
		return err
	}

	err = service.emailService.SendPasswordResetCode(tokenStr, *user.Email, *user.Name, req.RedirectURL)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to email password reset code [Email=%s]", *user.Email))
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully sent password reset code to %s", req.Email))
	return nil
}

func (service *Service) ResetPassword(req ResetPasswordRequest) error {
	if req.Password != req.PasswordConfirm {
		return ErrPasswordDoesNotMatch
	}

	claims := &ResetPasswordClaims{}
	err := token.ValidateToken(req.Data, claims)

	if err != nil {
		errStr := fmt.Sprintf("token validation failed, %s", err)
		service.loggingService.Print("FAIL", errStr)
		return fmt.Errorf(errStr)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to hash password [Email=%s]", claims.ID))
		return err
	}

	user, err := service.GetUserByEmail(GetUserByEmailRequest{Email: claims.Email})
	if err != nil {
		if err == database.ErrNotFound {
			service.loggingService.Print("FAIL", fmt.Sprintf("user not registered. [Email=%s]", claims.Email))
			return ErrUserDoesNotExist
		} else {
			service.loggingService.Print("FAIL", fmt.Sprintf("failed to get user from database. [Email=%s] [Err=%s]", claims.Email, err))
			return err
		}
	}

	if !*user.PasswordResetRequested {
		return ErrPasswordResetNotRequested
	}

	if *user.PasswordResetCode != claims.PasswordResetCode {
		return ErrIncorrectPasswordResetCode
	}

	now := time.Now()
	userUpdates := models.User{ID: user.ID}
	userUpdates.UpdatedAt = utils.ToPointer(now.UnixMilli())
	userUpdates.Password = utils.ToPointer(string(hashedPassword))
	userUpdates.EmailVerified = utils.ToPointer(true)           // if user could access password reset code, that means user owns that email.
	userUpdates.PasswordResetRequested = utils.ToPointer(false) // if password is resetted, PasswordResetCode is cleared

	err = service.db.UpdateUser(userUpdates, []string{}, []string{})
	if err != nil {
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully resetted password %s", claims.Email))
	return nil
}

func (service *Service) UpdatePassword(req UpdatePasswordRequest) error {
	if req.Password != req.PasswordConfirm {
		return ErrPasswordDoesNotMatch
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to hash password [ID=%s]", req.UserID))
		return err
	}

	err = service.UpdateUser(UpdateUserRequest{UserID: req.UserID, Password: utils.ToPointer(string(hashedPassword))})
	if err != nil {
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully updated password %s", req.UserID))
	return nil
}

func (service *Service) UpdateUser(req UpdateUserRequest) error {
	now := time.Now()
	updates := models.User{}
	updates.ID = &req.UserID
	updates.Name = req.Name
	updates.Password = req.Password
	updates.Data = req.Data
	updates.UpdatedAt = utils.ToPointer(now.UnixMilli())

	err := service.db.UpdateUser(updates, []string{}, []string{})
	if err != nil {
		return err
	}

	service.loggingService.Print("INFO", fmt.Sprintf("successfully updated user!"))
	return nil
}

func (service *Service) ReadUsers(req ReadUsersRequest) (res ReadUsersResponse, err error) {
	out, err := service.db.ReadUsers(database.ReadUsersRequest{
		ReadRequest: database.ReadRequest{
			Skip:      req.Skip,
			Limit:     req.Limit + 1, // reads extra item to check if the last page has reached
			SortOrder: database.OrderAsc,
		},
		SortField: database.SortFieldsMap.UserSortFields.Name,
		Roles:     req.Roles,
	})
	if err != nil {
		service.loggingService.Print("FAIL", fmt.Sprintf("failed to read users from db [REQ=%+v]", req))
		return res, err
	}

	res.Users = utils.ChanToSlice(out.Channel)
	res.Users, res.IsLastPage = utils.FitPageToLimit(res.Users, req.Limit)

	service.loggingService.Print("INFO", fmt.Sprintf("successfully read users from db"))

	return res, nil
}
