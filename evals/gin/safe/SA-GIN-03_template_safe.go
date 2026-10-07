package main

// SA-GIN-03: Safe template rendering — auto-escaping handles user input
import "github.com/gin-gonic/gin"

func profileHandler(c *gin.Context) {
	username := c.Query("name")
	c.HTML(200, "profile.html", gin.H{
		"username": username,
	})
}
