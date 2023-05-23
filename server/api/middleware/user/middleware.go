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

func (middleware *Middleware) GenAuthorizer(req GenAuthorizerRequest) func(c *gin.Context) {

	fn := func(c *gin.Context) {
		user, authorized, _ := middleware.userService.Authorize(userService.AuthorizeRequest{Token: token.ExtractToken(c), Role: req.Role})
		if !authorized {
			c.String(http.StatusUnauthorized, "token validation failed")
			c.Abort()
			return

		}
		c.Set("user", user)
		c.Next()
	}

	return fn
}

func (middleware *Middleware) VerifyMiddleware(c *gin.Context) {
	user := utils.GetValue[models.User](c, "user")
	if !*user.EmailVerified {
		c.String(http.StatusUnauthorized, "Please verify your email")
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
