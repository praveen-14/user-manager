package user

import (
	"github.com/praveen-14/user-manager/database/models"

	jwt "github.com/golang-jwt/jwt/v4"
)

type (
	AuthorizeRequest struct {
		Token string
	}

	GetUserRequest struct {
		UserID string
	}

	ValidateSessionRequest struct {
		UserID string
		Token  string
	}

	RegisterRequest struct {
		Email           string
		Name            string
		Password        string
		PasswordConfirm string
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
		UserEmail         string
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
		User            models.User
		Password        string
		PasswordConfirm string
	}

	UpdateUserRequest struct {
		User *models.User
		Name string
	}
)