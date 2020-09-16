package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"flag"

	filter "github.com/tickemaster/authentication/gin"
)

func main() {
	flag.Parse()
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	err := filter.UseAuthentication(r, filter.NewAuthenticationOptions())
	if err != nil {
		glog.Error(err)
	}
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/test")
	})
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "It works"})
	})
	r.GET("/test/fail", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "You shouldn't see this"})
	})

	r.Run(":9001")
}

func handleRequest(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"message": "MyTestResponse"})
}
