package utils

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/gin-gonic/gin"
	"github.com/praveen-14/user-manager/services/logger"
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

func GetValue[T any](c *gin.Context, key string) (*T, error) {
	v, ok := c.Get(key)
	if !ok {
		return nil, fmt.Errorf("key '%s' not found in context", key)
	}
	out := v.(T)
	return &out, nil
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

type (
	Response struct {
		Code    int    `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
		Data    any    `json:"data,omitempty"`
	}
)

func (res *Response) Dump(logger *logger.Service) []byte {
	b, err := json.Marshal(res)
	if err != nil {
		logger.Print("FAIL", fmt.Sprintf("could not marshal message [ERR: %s]", err))
	}

	return b
}

func Respond(c *gin.Context, logger *logger.Service, code int, message string, data any) {
	resp := &Response{
		Code:    code,
		Message: message,
		Data:    data,
	}

	buf := bytes.Buffer{}
	gz := gzip.NewWriter(&buf)
	gz.Write(resp.Dump(logger))
	gz.Close()

	c.Header("Content-Encoding", "gzip")
	c.Data(code, "application/json", buf.Bytes())

	// rw.Header().Set("Content-Type")
	// rw.Header().Set("Content-Encoding", "gzip")
	// rw.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

	// rw.WriteHeader(code)
	// rw.Write()

}

func ChanToSlice[T any](input <-chan T) []T {
	output := make([]T, 0)
	for i := range input {
		output = append(output, i)
	}
	return output
}
