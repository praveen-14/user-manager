package user

type (
	RegisterRequest struct {
		Email           string         `json:"email" binding:"required"`
		Name            string         `json:"name" binding:"required"`
		MobileNumber    string         `json:"mobile_number" binding:"required"`
		Password        string         `json:"password" binding:"required"`
		PasswordConfirm string         `json:"password_confirm" binding:"required"`
		Data            map[string]any `json:"data" binding:"required"`
		RedirectURL     string         `json:"redirect_url" binding:"required"` // url of frontend page where password verification status will be displayed. Verification code will be sent as a query param to this url in a GET request
	}

	LoginRequest struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	VerifyEmailRequest struct {
		Data string `json:"data" binding:"required"`
	}

	ForgotPasswordRequest struct {
		Email       string `json:"email" binding:"required"`
		RedirectURL string `json:"redirect_url" binding:"required"` // url of frontend page where new password can be typed. Password reset code will be sent as a query param to this url in a GET request
	}

	ResetPasswordRequest struct {
		Data            string `json:"data" binding:"required"`
		Password        string `json:"password" binding:"required"`
		PasswordConfirm string `json:"password_confirm" binding:"required"`
	}

	UpdatePasswordRequest struct {
		Password        string `json:"password" binding:"required"`
		PasswordConfirm string `json:"password_confirm" binding:"required"`
	}

	UpdateUserRequest struct {
		Name string `json:"name" binding:"required"`
	}

	UserInfoResponse struct {
		// need to add other required fields
		Name string
	}
)
