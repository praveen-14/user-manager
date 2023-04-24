package common

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"

	"github.com/praveen-14/user-manager/services/logger"

	"github.com/gin-gonic/gin"
)

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
