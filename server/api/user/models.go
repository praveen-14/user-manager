package user

type (
	RegisterRequest struct {
		Email           string `json:"email" binding:"required"`
		Name            string `json:"name" binding:"required"`
		MobileNumber    string `json:"mobile_number" binding:"required"`
		Password        string `json:"password" binding:"required"`
		PasswordConfirm string `json:"password_confirm" binding:"required"`
		RedirectURL     string `json:"redirect_url" binding:"required"` // url of frontend page where password verification status will be displayed. Verification code will be sent as a query param to this url in a GET request
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

	// UserInfoResponse represents the authenticated user's information
	// @Description User information response for authenticated users
	UserInfoResponse struct {
		ID             string         `json:"id"`
		Email          string         `json:"email"`
		Name           string         `json:"name"`
		Role           *string        `json:"role,omitempty"`
		MobileNumber   *string        `json:"mobile_number,omitempty"`
		EmailVerified  *bool          `json:"email_verified,omitempty"`
		UserVerified   *bool          `json:"user_verified,omitempty"`
		CreatedAt      *int64         `json:"created_at,omitempty"`
		UpdatedAt      *int64         `json:"updated_at,omitempty"`
		LastLoggedInAt *int64         `json:"last_logged_in_at,omitempty"`
		Tags           []string       `json:"tags,omitempty"`
		Data           map[string]any `json:"data,omitempty"`
	}

	// LoginResponse represents the response structure for user login
	// @Description Login response containing authentication token and user information
	LoginResponse struct {
		Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."` // JWT authentication token
		Name  string `json:"name" example:"John Doe"`                                 // User's name
		Role  string `json:"role" example:"user"`                                     // User's role
	}

	// Response represents a standard API response
	// @Description Standard API response structure
	Response struct {
		Code    int    `json:"code,omitempty" example:"200"`        // HTTP status code
		Message string `json:"message,omitempty" example:"Success"` // Response message
		Data    any    `json:"data,omitempty"`                      // Response data payload
	}
)
