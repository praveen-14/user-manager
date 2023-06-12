package models

type (
	User struct {
		ID                     *string         `json:"id,omitempty"`    // randomly generated int
		Email                  *string         `json:"email,omitempty"` // email
		Password               *string         `json:"password,omitempty"`
		Name                   *string         `json:"name,omitempty"`
		MobileNumber           *string         `json:"mobile_number,omitempty"`
		Role                   *string         `json:"role,omitempty"`
		EmailVerified          *bool           `json:"email_verified,omitempty"`
		EmailVerificationCode  *string         `json:"email_verification_code,omitempty"`
		PasswordResetCode      *string         `json:"password_reset_code,omitempty"`
		PasswordResetRequested *bool           `json:"password_reset_requested,omitempty"`
		CreatedAt              *int64          `json:"created_at,omitempty"`
		UpdatedAt              *int64          `json:"updated_at,omitempty"` // update time neglecting updates to login time
		LastLoggedInAt         *int64          `json:"last_logged_in_at,omitempty"`
		Deleted                *bool           `json:"deleted,omitempty"`
		Token                  *string         `json:"token,omitempty"` // used to make sure only one session is allowed for one user
		Tags                   *[]string       `json:"tags,omitempty"`
		Data                   *map[string]any `json:"data,omitempty"`
	}
)
