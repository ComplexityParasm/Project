package main

import (
	"go-auth/auth"     // Локальный импорт пакета auth
	"go-auth/database" // Локальный импорт пакета database
	"go-auth/handlers" // Локальный импорт пакета handlers
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv" // Импорт библиотеки для работы с .env файлами
)

func main() {
	// Загрузка переменных из .env файла
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Инициализация MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	err = database.InitMongoDB(mongoURI)
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

	// Загружаем шаблоны из папки templates
	r.LoadHTMLGlob("templates/*")

	// Добавляем маршруты
	r.GET("/", handlers.IndexHandler)
	r.GET("/auth/yandex", handlers.YandexAuthHandler)         // Авторизация через Яндекс
	r.GET("/auth/github", handlers.GithubAuthHandler)         // Авторизация через GitHub
	r.GET("/login", handlers.LoginHandler)                    // Проверка статуса пользователя
	r.GET("/yandex/login", handlers.YandexLoginHandler)       // Логин через Яндекс
	r.GET("/yandex/callback", handlers.YandexCallbackHandler) // Коллбек для Яндекса
	r.GET("/github/login", handlers.GitHubLoginHandler)       // Логин через Гитхаб
	r.GET("/github/callback", handlers.GitHubCallbackHandler) // Коллбек для Гитхаб
	r.POST("/verify_code", handlers.VerifyCodeHandler)
	r.GET("/request_code", handlers.RequestCodeForm)     // Форма запроса кода
	r.POST("/request_code", handlers.RequestCodeHandler) // Обработка отправки email
	r.GET("/create_test", handlers.CreateTestPage)
	r.POST("/api/tests", handlers.SubmitTestHandler)
	r.Static("/static", "./static")

	// Приватные маршруты с AuthMiddleware
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		panic("JWT_SECRET_KEY is not set")
	}
	protected := r.Group("/protected")
	protected.Use(auth.AuthMiddleware(secretKey))
	{
		protected.GET("/", handlers.ProtectedHandler)
	}

	log.Println("REDIS_ADDR:", os.Getenv("REDIS_ADDR"))

	// Запуск сервера
	r.Run(":8080")
}
