package main

// SA-GIN-01: Correct middleware ordering — auth before routes
import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	api := r.Group("/api")
	api.Use(requireAuth())
	api.GET("/users", listUsers)
	api.DELETE("/users/:id", deleteUser)

	r.GET("/health", healthCheck)

	r.Run(":8080")
}
