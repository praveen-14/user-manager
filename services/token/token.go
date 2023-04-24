package token

import (
	"strings"
	"user-manager/config"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func GenerateToken[T jwt.Claims](claims T) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.API_SECRET))
}

func ValidateToken[T jwt.Claims](token string, claims T) (err error) {
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.API_SECRET), nil
	})
	return err
}

func ExtractToken(c *gin.Context) string {
	bearerToken := c.Request.Header.Get("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
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
