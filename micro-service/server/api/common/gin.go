package common

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func GetValue[T any](c *gin.Context, key string) T {
	v, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("key '%s' not found in context", key))
	}
	return v.(T)
}
