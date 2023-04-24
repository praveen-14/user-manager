package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"user-manager/config"
	"user-manager/database"
	"user-manager/server/api"
	"user-manager/services/logger"
)

const (
	MEMORY_LIMIT = 10 << 20
)

var (
	instance *Server
	once     sync.Once
)

type (
	Server struct {
		*http.Server

		loggingService *logger.Service
	}
)

func New(db database.Database) (*Server, error) {
	var err error
	once.Do(func() {
		api, err1 := api.New(db)
		if err1 != nil {
			err = err1
			return
		}

		server := &http.Server{
			Addr:              fmt.Sprintf(":%d", config.APIPORT),
			Handler:           http.MaxBytesHandler(api.Engine, int64(MEMORY_LIMIT)),
			ReadHeaderTimeout: 2 * time.Minute,
			IdleTimeout:       2 * time.Minute,
			WriteTimeout:      2 * time.Minute,
			MaxHeaderBytes:    1 << 20,
		}

		instance = &Server{
			loggingService: logger.New("server", 0),
			Server:         server,
		}
	})

	return instance, err
}

func (server *Server) Run() {
	defer server.Close()

	err := server.Server.ListenAndServe()
	if err != nil {
		server.loggingService.Print("FAIL", "running API server", err)
	} else {
		server.loggingService.Print("INFO", "exiting API server")
	}
}
