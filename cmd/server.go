package main

import (
	"go-auth/auth"     // Локальный импорт пакета auth
	"go-auth/database" // Локальный импорт пакета database
	"go-auth/handlers" // Локальный импорт пакета handlers
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// Инициализация MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	err := database.InitMongoDB(mongoURI)
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	
	// Инициализация Redis
	err = auth.InitRedis()
	if err != nil {
		log.Fatal("Error connecting to Redis:", err)
	}

	// Инициализация Gin
	r := gin.Default()

	// Маршруты
	r.GET("/", handlers.IndexHandler)
	r.POST("/login", handlers.LoginHandler)
	r.POST("/register", handlers.RegisterHandler)
	r.GET("/protected", handlers.ProtectedHandler)

	// Запуск сервера
	r.Run(":8080")
}
