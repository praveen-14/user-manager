package common

import (
	"net/http"
	"user-manager/database/models"
	"user-manager/services/token"
	userService "user-manager/services/user"
	"user-manager/utils"

	"github.com/gin-gonic/gin"
)

func AuthMiddlewareGene(userServ *userService.Service) func(c *gin.Context) {

	fn := func(c *gin.Context) {
		user, authorized, _ := userServ.Authorize(userService.AuthorizeRequest{Token: token.ExtractToken(c)})
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

func VerifyMiddleware(c *gin.Context) {
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
