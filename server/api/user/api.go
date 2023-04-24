package user

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	"github.com/praveen-14/user-manager/server/api/common"
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
	userService *userServiceMod.Service

	loggingService *logger.Service
}

func New(db database.Database) (*Api, error) {
	var err error
	once.Do(func() {
		if userService, err1 := userServiceMod.New(db); err1 != nil {
			err = err1
			return
		} else {
			instance = &Api{
				loggingService: logger.New("user-api", 0),
				userService:    userService,
			}
		}

	})
	return instance, err
}

func (api *Api) AddRoutesTo(router *gin.RouterGroup) {
	routerGrp := router.Group("/user")
	{
		// public apis
		routerGrp.POST("/register", func(c *gin.Context) { api.RegisterUser(c) })
		routerGrp.POST("/login", func(c *gin.Context) { api.LoginUser(c) })
		routerGrp.POST("/forgot-password", func(c *gin.Context) { api.ForgotPassword(c) })
		routerGrp.POST("/reset-password", func(c *gin.Context) { api.ResetPassword(c) })
		routerGrp.POST("/verify-email", func(c *gin.Context) { api.VerifyEmail(c) })

		// apis added after this middleware cannot be invoked without logging in
		routerGrp.Use(common.AuthMiddlewareGene(api.userService))

		// apis added after this middleware cannot be invoked without verifying the email
		routerGrp.Use(common.VerifyMiddleware)

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
// @Success 	200 				{object} 	common.Response
// @Router 		/user/register 		[post]
func (api *Api) RegisterUser(c *gin.Context) {

	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.RegisterUser(userServiceMod.RegisterRequest(req)); err != nil {
		if err == userServiceMod.ErrPasswordDoesNotMatch {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Password doesn't match", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrUserExists {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User already exists!", utils.GetJsonBodyFromGinContext(c))
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "User registartion successful!", req)
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
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
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

	res, err := api.userService.LoginUser(userServiceMod.LoginRequest{Email: req.Email, Password: req.Password, IP: ip})
	if err != nil {
		switch err {
		case userServiceMod.ErrUserDoesNotExist:
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
		case userServiceMod.ErrIncorrectPassword:
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect password!", utils.GetJsonBodyFromGinContext(c))
		default:
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
		}
		return
	}

	common.Respond(
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
// @Success 	200 			{object} 	user.AuthUserInfo
// @Param 		Authorization 		header 		string 				true 	"Example: Bearer _token_"
// @Router 		/user/info 	[post]
func (api *Api) UserInfo(c *gin.Context) {
	user := utils.GetValue[models.User](c, "user")

	res := UserInfoResponse{
		// need to add other required fields
		Name: *user.Name,
	}

	// user, err := api.userService.AuthUserInfo(userID)
	// if err != nil {
	// 	common.Respond(c, api.loggingService, http.StatusUnauthorized, "Unable to get user info!", ":0")
	// 	return
	// }

	common.Respond(
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
// @Param       data   			body      	VerifyRequest		  	true  	"data"
// @Success 	200 			{object} 	common.Response
// @Router 		/user/verify-email 	[post]
func (api *Api) VerifyEmail(c *gin.Context) {

	var req VerifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		api.loggingService.Print("FAIL", "request verification failed [ERR=%s]", err)
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	err := api.userService.VerifyEmail(userServiceMod.VerifyRequest(req))
	if err != nil {
		if err == userServiceMod.ErrIncorrectValidationCode {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect validation code", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrUserDoesNotExist {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User does not exist!", utils.GetJsonBodyFromGinContext(c))
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "Email verification successful!", req)
}

// @Summary 	Forgot password
// @Description Forgot password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	ForgotPasswordRequest		true  	"email"
// @Success 	200 					{object} 	common.Response
// @Router 		/user/forgot-password 	[post]
func (api *Api) ForgotPassword(c *gin.Context) {

	var req ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.ForgotPassword(userServiceMod.ForgotPasswordRequest(req)); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "Password reset code sent successfully!", req)
}

// @Summary 	Reset password
// @Description Reset password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	ResetPasswordRequest		true  	"reset password data"
// @Success 	200 					{object} 	common.Response
// @Router 		/user/reset-password 	[post]
func (api *Api) ResetPassword(c *gin.Context) {

	var req ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.ResetPassword(userServiceMod.ResetPasswordRequest(req)); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrIncorrectPasswordResetCode {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Incorrect password reset code!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordResetNotRequested {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Password reset not requested!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordDoesNotMatch {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Passwords don't match", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "Successfully resetted password!", req)
}

// @Summary 	Update password
// @Description Update password
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	UpdatePasswordRequest		true  	"update password data"
// @Param 		Authorization 			header 		string 						true 	"Example: Bearer _token_"
// @Success 	200 					{object} 	common.Response
// @Router 		/user/update-password 	[post]
func (api *Api) UpdatePassword(c *gin.Context) {

	var req UpdatePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Print(err)
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.UpdatePassword(userServiceMod.UpdatePasswordRequest{User: utils.GetValue[models.User](c, "user"), Password: req.Password, PasswordConfirm: req.PasswordConfirm}); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else if err == userServiceMod.ErrPasswordDoesNotMatch {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "Passwords don't match", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "Successfully updated password!", "")
}

// @Summary 	Update user info
// @Description Update user info
// @Tags 		User
// @Accept  	json
// @Produce  	json
// @Param       data   					body      	UpdateUserRequest		true  	"update user info data"
// @Param 		Authorization 			header 		string 						true 	"Example: Bearer _token_"
// @Success 	200 					{object} 	common.Response[UpdateUserRequest]
// @Router 		/user/update-info 		[post]
func (api *Api) UpdateInfo(c *gin.Context) {

	var req UpdateUserRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Print(err)
		common.Respond(c, api.loggingService, http.StatusBadRequest, "User data validation failed!", utils.GetJsonBodyFromGinContext(c))
		return
	}

	if err := api.userService.UpdateUser(userServiceMod.UpdateUserRequest{User: utils.GetValue[*models.User](c, "user"), Name: req.Name}); err != nil {
		if err == userServiceMod.ErrUserDoesNotExist {
			common.Respond(c, api.loggingService, http.StatusBadRequest, "User not registered!", utils.GetJsonBodyFromGinContext(c))
			return
		} else {
			common.Respond(c, api.loggingService, http.StatusInternalServerError, "Server Error!", ":O")
			return
		}
	}

	common.Respond(c, api.loggingService, http.StatusOK, "Successfully updated user info!", req)
}
