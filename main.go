package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	ginlogrus "github.com/toorop/gin-logrus"
)

func main() {
	_ = NewOAuth2Server()

	g := gin.New()
	g.Use(ginlogrus.Logger(logrus.New()))
	g.Use(gin.Recovery())

	oauth2 := g.Group("/oauth2")
	{
		oauth2.GET("/identicate", IdenticateGet)       // Step 2.1
		oauth2.GET("/authenticate", AuthenticateGet)   // Step 1.1
		oauth2.POST("/authenticate", AuthenticatePost) // Step 2
		oauth2.GET("/authorize", AuthorizeAny)         // Step 1
		oauth2.POST("/authorize", AuthorizeAny)        // Step 3
		oauth2.GET("/token", TokenGet)                 // Step 4
	}

	_ = g.Run(":8080")
}
