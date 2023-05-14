package utils

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"

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

func GetAllFilenames(efs *embed.FS) (files []string, err error) {
	if err := fs.WalkDir(efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func GetUniqueValues(arr []string) []string {
	out := make([]string, 0)
	found := map[string]bool{}
	for _, item := range arr {
		_, ok := found[item]
		if !ok {
			out = append(out, item)
			found[item] = true
		}
	}
	return out
}

func PrintObj(v any) {
	fmt.Printf("%+v", v)
}
