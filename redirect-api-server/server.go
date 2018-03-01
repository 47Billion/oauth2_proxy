package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/apex/log"
	"fmt"
)

const (
	RBACServerPort = ":9091"
)

func main() {
	router := gin.Default()

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "pong"})
	})

	// Google Redirect URL
	router.POST("/47billion/oauth2/callback", handler)

	/*// FB Redirect URL
	router.GET("/fb/oauth2/callback", handler.Facebook)

	// Github Redirect URL
	router.GET("/github/oauth2/callback", handler.Github)*/


	// Google Redirect URL
	router.POST("/tile38", tile38Handler)

	router.Run(RBACServerPort)
}

func handler(c *gin.Context) {
	var response map[string]string

	err := c.BindJSON(&response)
	if nil != err {
		log.Errorf("handler() Unable to bind response err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	fmt.Printf("token= %+v", response)
	c.JSON(200, gin.H{"msg": "ok", "token": response})
}

func tile38Handler(c *gin.Context) {
	var response map[string]interface{}

	err := c.BindJSON(&response)
	if nil != err {
		log.Errorf("handler() Unable to bind response err=%+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	fmt.Printf("token= %+v", response)
	c.JSON(200, gin.H{"msg": "ok", "token": response})
}