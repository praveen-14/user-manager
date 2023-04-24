package utils

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
)

type ConstError string

func (e ConstError) Error() string { return string(e) }

// type PointableError struct {
// 	s string
// }

// func NewPointableError(text string) error {
// 	return &PointableError{text}
// }

// func (e *PointableError) Error() string {
// 	return e.s
// }

func String(data interface{}) string {
	dat, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return ""
	}

	return "\n" + string(dat) + "\n"
}

func GetJsonBodyFromGinContext(c *gin.Context) map[string]interface{} {
	var data map[string]interface{}
	c.ShouldBindJSON(&data)
	return data
}

func ToPointer[T any](a T) *T {
	return &a
}

func ToDict(obj any) (out map[string]interface{}) {
	out = map[string]interface{}{}
	inrec, err := json.Marshal(obj)
	if err != nil {
		panic(fmt.Sprintf("object encoding failed (Marshal step), obj = %+v, err = %s", obj, err))
	}
	err = json.Unmarshal(inrec, &out)
	if err != nil {
		panic(fmt.Sprintf("object encoding failed (Unmarshal step), obj = %+v, err = %s", obj, err))
	}
	return out
}

func ToObj[T any](dict any, objPtr *T) {
	inrec, err := json.Marshal(dict)
	if err != nil {
		panic(fmt.Sprintf("object decoding failed (Marshal step), obj = %+v, err = %s", objPtr, err))
	}
	err = json.Unmarshal(inrec, objPtr)
	if err != nil {
		panic(fmt.Sprintf("object decoding failed (Unmarshal step), obj = %+v, err = %s", objPtr, err))
	}
}

func GetValue[T any](c *gin.Context, key string) T {
	v, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("key '%s' not found in context", key))
	}
	return v.(T)
}
