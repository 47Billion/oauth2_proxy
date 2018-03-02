package main

import (
	"net/http"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/apex/log"
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
	router.GET("/47billion/oauth2/callback", handler)

	// Tile38 sample URL
	router.POST("/tile38", tile38Handler)

	router.Run(RBACServerPort)
}

func handler(c *gin.Context) {
	var token = c.Query("token")
	fmt.Printf("token= %+v", token)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
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
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "token": response})
}