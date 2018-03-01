package api_server

import (
	"github.com/47Billion/oauth2_proxy/api-server/handler"

	"github.com/gin-gonic/gin"
)

const (
	RBACServerPort = ":9090"
)

func StartServer() {
	router := gin.Default()

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "pong"})
	})

	// Google Redirect URL
	router.GET("/google/oauth2/callback", handler.Google)

	// FB Redirect URL
	router.GET("/fb/oauth2/callback", handler.Facebook)

	// Github Redirect URL
	router.GET("/github/oauth2/callback", handler.Github)

	router.Run(RBACServerPort)
}
