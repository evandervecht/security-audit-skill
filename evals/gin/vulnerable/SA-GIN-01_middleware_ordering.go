package main

// SA-GIN-01: Auth middleware registered after route handlers
import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	api := r.Group("/api")
	api.GET("/users", listUsers)
	api.DELETE("/users/:id", deleteUser)

	r.Use(authMiddleware())

	r.Run(":8080")
}
