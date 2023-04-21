package api

import (
	"sync"
	"user-manager/database"
	"user-manager/docs"
	userApi "user-manager/server/api/user"
	"user-manager/services/logger"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var (
	api  *Api
	once sync.Once
)

type Api struct {
	*gin.Engine
	userApi        *userApi.Api
	loggingService *logger.Service
}

func New(db database.Database) (*Api, error) {

	var err error
	once.Do(func() {
		docs.SwaggerInfo.BasePath = "/api/v1"

		r := gin.New()
		r.Use(cors.New(cors.Config{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST", "OPTIONS"},
			AllowHeaders: []string{
				"Accept",
				"Authorization",
				"Origin",
				"Content-Type",
				"X-Client-Key",
				"X-Client-Secret",
				"X-Client-Token",
				"X-Requested-With",
			},
			ExposeHeaders: []string{
				"Content-Length",
				"Filename",
			},
			AllowCredentials: true,
			AllowOriginFunc: func(origin string) bool {
				return true
			},
			MaxAge: 86400,
		}))

		apiRouter := r.Group("/api/v1")

		// status check endpoint
		apiRouter.GET("/status", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Available!",
			})
		})

		api = &Api{
			loggingService: logger.New("api", 0),
			Engine:         r,
		}

		api.userApi, err = userApi.New(db)
		if err != nil {
			return
		}

		api.userApi.AddRoutesTo(apiRouter)

		// public apis
		apiRouter.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	})

	return api, err
}
