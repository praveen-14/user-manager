package token

import (
	"errors"
	"strings"

	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/utils"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	ErrSessionTimedOut = utils.ConstError("session timed out")
)

func GenerateToken[T jwt.Claims](claims T) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.API_SECRET))
}

func ValidateToken[T jwt.Claims](tokenStr string, claims T) error {
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.API_SECRET), nil
	})
	if err == nil {
		return nil
	}

	var validationErr *jwt.ValidationError
	if errors.As(err, &validationErr) && validationErr.Errors&jwt.ValidationErrorExpired != 0 {
		return ErrSessionTimedOut
	}
	return err
}

func ExtractToken(c *gin.Context) string {
	bearerToken := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	if bearerToken == "" {
		return ""
	}

	parts := strings.Fields(bearerToken)
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		if strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	return ""
}

// func ExtractTokenID(c *gin.Context) (string, error) {
// 	tokenString := ExtractToken(c)
// 	claims := Claims{}
// 	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
// 		return []byte(config.API_SECRET), nil
// 	})
// 	if err != nil {
// 		return "", err
// 	}
// 	return claims.UserID, nil
// }
