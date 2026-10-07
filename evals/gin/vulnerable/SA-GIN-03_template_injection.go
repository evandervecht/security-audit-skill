package main

// SA-GIN-03: User input cast to template.HTML bypasses auto-escaping
import (
	"html/template"

	"github.com/gin-gonic/gin"
)

func profileHandler(c *gin.Context) {
	username := c.Query("name")
	c.HTML(200, "profile.html", gin.H{
		"username": template.HTML(username),
	})
}
