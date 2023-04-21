package common

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"user-manager/services/logger"

	"github.com/gin-gonic/gin"
)

type (
	Response struct {
		Code    int         `json:"code,omitempty"`
		Message string      `json:"message,omitempty"`
		Data    interface{} `json:"data,omitempty"`
	}
)

func (res *Response) Dump(logger *logger.Service) []byte {
	b, err := json.Marshal(res)
	if err != nil {
		logger.Print("FAIL", fmt.Sprintf("could not marshal message [ERR: %s]", err))
	}

	return b
}

func Respond(c *gin.Context, logger *logger.Service, code int, message string, data ...interface{}) {
	resp := &Response{
		Code:    code,
		Message: message,
	}

	if len(data) > 0 {
		if len(data) > 1 {
			resp.Data = data
		} else {
			resp.Data = data[0]
		}
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
