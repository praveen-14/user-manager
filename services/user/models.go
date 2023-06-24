package user

import (
	"github.com/praveen-14/user-manager/database/models"

	jwt "github.com/golang-jwt/jwt/v4"
)

type (
	AuthorizeTokenRequest struct {
		Token        string
		AllowedRoles []string
	}

	AuthorizeUserRequest struct {
		User         models.User
		AllowedRoles []string
	}

	GetUserRequest struct {
		UserID string
	}

	GetUserByEmailRequest struct {
		Email string
	}

	GetUsersRequest struct {
		UserIDs []string
	}

	RegisterRequest struct {
		Email           string
		Role            string
		Name            string
		MobileNumber    string
		Password        string
		PasswordConfirm string
		Data            map[string]any
		RedirectURL     string
	}

	VerifyClaims struct {
		UserID           string
		VerificationCode string
		jwt.RegisteredClaims
	}

	LoginRequest struct {
		Email    string
		Password string
		IP       string
	}

	LoginResponse struct {
		Token string `json:"token"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}

	AuthUserInfo struct {
		*models.User
	}

	VerifyRequest struct {
		Data string
	}

	AuthClaims struct {
		UserID    string
		UserEmail string
		jwt.RegisteredClaims
	}

	ResetPasswordClaims struct {
		Email             string
		PasswordResetCode string
		jwt.RegisteredClaims
	}

	ForgotPasswordRequest struct {
		Email       string
		RedirectURL string
	}

	ResetPasswordRequest struct {
		Data            string
		Password        string
		PasswordConfirm string
	}

	UpdatePasswordRequest struct {
		UserID          string
		Password        string
		PasswordConfirm string
	}

	UpdateUserRequest struct {
		UserID   string
		Password *string         // not updated if nil
		Name     *string         // not updated if nil
		Data     *map[string]any // not updated if nil
	}

	ReadUsersRequest struct {
		Skip  int      `json:"skip"`
		Limit int      `json:"limit"`
		Roles []string `json:"roles"`
	}

	ReadUsersResponse struct {
		IsLastPage bool           `json:"is_last_page"`
		Users      []*models.User `json:"users"`
	}
)
