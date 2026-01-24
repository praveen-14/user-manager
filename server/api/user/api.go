package user

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	userMiddleware "github.com/praveen-14/user-manager/server/api/middleware/user"
	"github.com/praveen-14/user-manager/services/logger"
	userServiceMod "github.com/praveen-14/user-manager/services/user"
	"github.com/praveen-14/user-manager/utils"

	"github.com/gin-gonic/gin"
)

var (
	instance *Api
	once     sync.Once
)

type Api struct {
	userService              *userServiceMod.Service
	userMiddleare            *userMiddleware.Middleware
	loginChecks              []func(*models.User) error
	loginChecksErrorMessages map[error]string

	loggingService *logger.Service
}

func New(db database.Database, loginChecks []func(*models.User) error, loginChecksErrorMessages map[error]string) (*Api, error) {
	var err error
	once.Do(func() {
		userService, err1 := userServiceMod.New(db)
		if err1 != nil {
			err = err1
			return
		}

		userMiddleware, err1 := userMiddleware.New(db)
		if err1 != nil {
			err = err1
			return
		}

		instance = &Api{
			loggingService:           logger.New("user-api", 0),
			userService:              userService,
			userMiddleare:            userMiddleware,
			loginChecks:              loginChecks,
			loginChecksErrorMessages: loginChecksErrorMessages,
		}

	})
	return instance, err
}

func (api *Api) AddRoutesTo(router *gin.RouterGroup) {
	routerGrp := router.Group("/user")
	{
		// public apis
		routerGrp.POST("/register", func(c *gin.Context) { api.RegisterUser(c) })
		routerGrp.POST("/forgot-password", func(c *gin.Context) { api.ForgotPassword(c) })
		routerGrp.POST("/reset-password", func(c *gin.Context) { api.ResetPassword(c) })
		routerGrp.POST("/verify-email", func(c *gin.Context) { api.VerifyEmail(c) })
		routerGrp.POST("/login", func(c *gin.Context) { api.LoginUser(c) })

		// apis added after this middleware cannot be invoked without logging in
		routerGrp.Use(api.userMiddleare.GenAuthorizer(userMiddleware.GenAuthorizerRequest{AllowedRolesRegex: ".*"}))

		// apis added after this middleware cannot be invoked without verifying the email
		routerGrp.Use(api.userMiddleare.VerifyMiddleware)

		routerGrp.POST("/info", func(c *gin.Context) { api.UserInfo(c) })
		routerGrp.POST("/update-password", func(c *gin.Context) { api.UpdatePassword(c) })
		routerGrp.POST("/update-info", func(c *gin.Context) { api.UpdateInfo(c) })
	}
}

// @Summary 	Register user
// @Description Register user
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       user   				body      	RegisterRequest 	true  	"User data"
// @Success 	200 				{object} 	user.Response
// @Router 		/user/register 		[post]
func (api *Api) RegisterUser(c *gin.Context) {

	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.RegisterUser(userServiceMod.RegisterRequest{
		Email:           req.Email,
		Name:            req.Name,
		MobileNumber:    req.MobileNumber,
		Password:        req.Password,
		PasswordConfirm: req.PasswordConfirm,
		RedirectURL:     req.RedirectURL,
	}); err != nil {
		if err == userServiceMod.ErrInternal {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
		} else {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, err.Error(), utils.GetJsonBodyFromGinContext(c))
		}
		return
	}

	utils.Respond(c, api.loggingService, http.StatusCreated, "User registartion successful!", req)
}

// @Summary 	Login user
// @Description Login user
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       user   			body      	LoginRequest  		true  "User data"
// @Success 	200 			{object} 	user.LoginResponse
// @Router 		/user/login 	[post]
func (api *Api) LoginUser(c *gin.Context) {

	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Print(err)
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	ip := ""
	forwarded := c.Request.Header["X-FORWARDED-FOR"]
	if len(forwarded) > 0 {
		ip = forwarded[0]
	}
	if ip == "" {
		ip = c.Request.RemoteAddr
	}

	res, err := api.userService.LoginUser(userServiceMod.LoginRequest{Email: req.Email, Password: req.Password, IP: ip, LoginChecks: api.loginChecks})
	if err != nil {
		value, exists := api.loginChecksErrorMessages[err]
		if exists {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, value, utils.GetJsonBodyFromGinContext(c))
			return
		}

		switch err {
		case userServiceMod.ErrUserDoesNotExist:
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
		case userServiceMod.ErrIncorrectPassword:
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect password!", utils.GetJsonBodyFromGinContext(c))
		case userServiceMod.ErrEmailNotVerified:
			utils.Respond(c, api.loggingService, http.StatusBadRequest, userServiceMod.ErrEmailNotVerified.Error(), utils.GetJsonBodyFromGinContext(c))
		default:
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
		}
		return
	}

	utils.Respond(
		c,
		api.loggingService,
		http.StatusOK,
		fmt.Sprintf("Welcome back %s!", res.Name),
		res,
	)
}

// @Summary 	User info
// @Description Get authenticated user's info
// @Tags 		User
// @Produce  	json
// @Success 	200 			{object} 	user.UserInfoResponse
// @Param 		Authorization 		header 		string 				true 	"Example: Bearer _token_"
// @Router 		/user/info 	[post]
func (api *Api) UserInfo(c *gin.Context) {
	// Log REQUEST details
	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("REQUEST: /api/v1/user/info")
	fmt.Println(separator)
	fmt.Printf("Method: %s\n", c.Request.Method)
	fmt.Printf("Path: %s\n", c.Request.URL.Path)
	fmt.Printf("Client IP: %s\n", c.ClientIP())
	fmt.Printf("User Agent: %s\n", c.Request.UserAgent())

	// Log headers (excluding sensitive ones)
	fmt.Println("\nHeaders:")
	for key, values := range c.Request.Header {
		if key != "Authorization" && key != "Cookie" {
			fmt.Printf("  %s: %s\n", key, values[0])
		} else if key == "Authorization" {
			fmt.Printf("  %s: [REDACTED]\n", key)
		}
	}

	// Log request body if present
	var requestBody map[string]interface{}
	if c.Request.Body != nil && c.Request.ContentLength > 0 {
		// Read the body
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		// Restore the body for subsequent handlers
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if len(bodyBytes) > 0 {
			if err := c.ShouldBindJSON(&requestBody); err == nil {
				fmt.Println("\nRequest Body:")
				fmt.Printf("  %+v\n", requestBody)
			} else {
				fmt.Println("\nRequest Body:")
				fmt.Printf("  %s\n", string(bodyBytes))
			}
		} else {
			fmt.Println("\nRequest Body: (empty)")
		}
	} else {
		fmt.Println("\nRequest Body: (empty)")
	}
	fmt.Println(separator + "\n")

	user, err := utils.GetValue[models.User](c, "user")
	if err != nil {
		errorResponse := map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": "Server Error!",
			"data":    ":O",
		}

		// Log ERROR RESPONSE
		fmt.Println(separator)
		fmt.Println("RESPONSE: /api/v1/user/info")
		fmt.Println(separator)
		fmt.Printf("Status Code: %d\n", http.StatusInternalServerError)
		fmt.Printf("Response: %+v\n", errorResponse)
		fmt.Println(separator + "\n")

		utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
		return
	}

	res := UserInfoResponse{
		Name: *user.Name,
	}

	if user.ID != nil {
		res.ID = *user.ID
	}
	if user.Email != nil {
		res.Email = *user.Email
	}
	if user.Role != nil {
		res.Role = user.Role
	}
	if user.MobileNumber != nil {
		res.MobileNumber = user.MobileNumber
	}
	if user.EmailVerified != nil {
		res.EmailVerified = user.EmailVerified
	}
	if user.UserVerified != nil {
		res.UserVerified = user.UserVerified
	}
	if user.CreatedAt != nil {
		res.CreatedAt = user.CreatedAt
	}
	if user.UpdatedAt != nil {
		res.UpdatedAt = user.UpdatedAt
	}
	if user.LastLoggedInAt != nil {
		res.LastLoggedInAt = user.LastLoggedInAt
	}
	if user.Tags != nil {
		res.Tags = *user.Tags
	}
	if user.Data != nil {
		res.Data = *user.Data
	}

	// Log SUCCESS RESPONSE
	fmt.Println(separator)
	fmt.Println("RESPONSE: /api/v1/user/info")
	fmt.Println(separator)
	fmt.Printf("Status Code: %d\n", http.StatusOK)
	fmt.Printf("Message: %s\n", fmt.Sprintf("Welcome back %s!", *user.Name))
	fmt.Println("\nResponse Data:")
	fmt.Printf("  %+v\n", res)
	fmt.Println(separator + "\n")

	utils.Respond(
		c,
		api.loggingService,
		http.StatusOK,
		fmt.Sprintf("Welcome back %s!", *user.Name),
		res,
	)
}

// @Summary 	Verify email
// @Description Verify email
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   			body      	VerifyEmailRequest		  	true  	"data"
// @Success 	200 			{object} 	user.Response
// @Router 		/user/verify-email 	[post]
func (api *Api) VerifyEmail(c *gin.Context) {

	var req VerifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		api.loggingService.Print("FAIL", "request verification failed [ERR=%s]", err)
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	err := api.userService.VerifyEmail(userServiceMod.VerifyRequest(req))
	if err != nil {
		if err == userServiceMod.ErrIncorrectValidationCode {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect validation code", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrUserDoesNotExist {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User does not exist!", utils.GetJsonBodyFromGinContext(c))
		} else {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	utils.Respond(c, api.loggingService, http.StatusOK, "Email verification successful!", req)
}

// @Summary 	Forgot password
// @Description Forgot password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	ForgotPasswordRequest		true  	"email"
// @Success 	200 					{object} 	user.Response
// @Router 		/user/forgot-password 	[post]
func (api *Api) ForgotPassword(c *gin.Context) {

	var req ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.ForgotPassword(userServiceMod.ForgotPasswordRequest(req)); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	utils.Respond(c, api.loggingService, http.StatusOK, "Password reset code sent successfully!", req)
}

// @Summary 	Reset password
// @Description Reset password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	ResetPasswordRequest		true  	"reset password data"
// @Success 	200 					{object} 	user.Response
// @Router 		/user/reset-password 	[post]
func (api *Api) ResetPassword(c *gin.Context) {

	var req ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.ResetPassword(userServiceMod.ResetPasswordRequest(req)); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrIncorrectPasswordResetCode {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect password reset code!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordResetNotRequested {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Password reset not requested!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordDoesNotMatch {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Passwords don't match", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	utils.Respond(c, api.loggingService, http.StatusOK, "Successfully resetted password!", req)
}

// @Summary 	Update password
// @Description Update password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	UpdatePasswordRequest		true  	"update password data"
// @Param 		Authorization 			header 		string 						true 	"Example: Bearer _token_"
// @Success 	200 					{object} 	user.Response
// @Router 		/user/update-password 	[post]
func (api *Api) UpdatePassword(c *gin.Context) {

	var req UpdatePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Print(err)
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	user, err := utils.GetValue[models.User](c, "user")
	if err != nil {
		utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
	}
	if err := api.userService.UpdatePassword(userServiceMod.UpdatePasswordRequest{UserID: *user.ID, Password: req.Password, PasswordConfirm: req.PasswordConfirm}); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordDoesNotMatch {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "Passwords don't match", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	utils.Respond(c, api.loggingService, http.StatusOK, "Successfully updated password!", "")
}

// @Summary 	Update user info
// @Description Update user info
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	UpdateUserRequest		true  	"update user info data"
// @Param 		Authorization 			header 		string 						true 	"Example: Bearer _token_"
// @Success 	200 					{object} 	user.Response
// @Router 		/user/update-info 		[post]
func (api *Api) UpdateInfo(c *gin.Context) {

	var req UpdateUserRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Print(err)
		utils.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	user, err := utils.GetValue[models.User](c, "user")
	if err != nil {
		utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
	}
	if err := api.userService.UpdateUser(userServiceMod.UpdateUserRequest{UserID: *user.ID, Name: &req.Name}); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			utils.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			utils.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	utils.Respond(c, api.loggingService, http.StatusOK, "Successfully updated user info!", req)
}
