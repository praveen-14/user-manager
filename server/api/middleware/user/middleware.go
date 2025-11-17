package user

import (
	"net/http"
	"sync"

	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	"github.com/praveen-14/user-manager/services/logger"
	"github.com/praveen-14/user-manager/services/token"
	"github.com/praveen-14/user-manager/services/user"
	userService "github.com/praveen-14/user-manager/services/user"
	"github.com/praveen-14/user-manager/utils"

	"github.com/gin-gonic/gin"
)

var (
	instance *Middleware
	once     sync.Once
)

type Middleware struct {
	userService *user.Service

	loggingService *logger.Service
}

func New(db database.Database) (*Middleware, error) {
	var err error
	once.Do(func() {
		userService, err1 := user.New(db)
		if err1 != nil {
			err = err1
			return
		}

		instance = &Middleware{
			loggingService: logger.New("user-middleware", 0),
			userService:    userService,
		}

	})
	return instance, err
}

// if the user is already in the context, that user object will be reused without taking user from database
func (middleware *Middleware) GenAuthorizer(req GenAuthorizerRequest) func(c *gin.Context) {

	fn := func(c *gin.Context) {
		user, err := utils.GetValue[models.User](c, "user")
		var authError error
		if err != nil { // user not in context
			_user, _authError := middleware.userService.AuthorizeToken(userService.AuthorizeTokenRequest{Token: token.ExtractToken(c), AllowedRolesRegex: req.AllowedRolesRegex})
			user = &_user
			authError = _authError
		} else {
			authError = middleware.userService.AuthorizeUser(userService.AuthorizeUserRequest{User: *user, AllowedRolesRegex: req.AllowedRolesRegex})
		}

		if authError != nil {
			if authError == userService.ErrSessionTimedOut {
				utils.Respond(c, middleware.loggingService, http.StatusUnauthorized, "session timed-out", ":(")

			}
			middleware.loggingService.Print("INFO", "authorization failed [ERR=%s]", authError)
			utils.Respond(c, middleware.loggingService, http.StatusUnauthorized, "authorization failed", ":(")
			c.Abort()
			return
		}
		c.Set("user", *user)
		c.Next()
		return
	}

	return fn
}

func (middleware *Middleware) VerifyMiddleware(c *gin.Context) {
	_user, err := utils.GetValue[models.User](c, "user")
	if err != nil {
		utils.Respond(c, middleware.loggingService, http.StatusInternalServerError, "Server error!", ":(")
		c.Abort()
		return
	}
	if !*_user.EmailVerified {
		utils.Respond(c, middleware.loggingService, http.StatusUnauthorized, user.ErrEmailNotVerified.Error(), ":(")
		c.Abort()
		return
	}
	c.Next()
}

// func SingleSessMiddlewareGene(userServ userService.Service) {

// 	fn := func(c *UserContext) {
// 		claims := &userService.AuthClaims{}
// 		err := token.ValidateToken(c, claims)
// 		if err != nil {
// 			userServ.Print("FAIL", "token validation failed")
// 			c.String(http.StatusUnauthorized, "Unauthorized")
// 			c.Abort()
// 			return
// 		}
// 		userServ.ValidateSession(userService.ValidateSessionRequest{UserID: })
// 	}

// 	return fn
// }
