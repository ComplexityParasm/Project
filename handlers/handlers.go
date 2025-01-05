package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go-auth/auth"
	"go-auth/database"
	"go-auth/models"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt/v4"

	//"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/mongo"
)

// Обработчик главной страницы!!!
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "Welcome",
	})
}

// Получение пользователя по токену
func getUserByEntryToken(entryToken string) (*models.User, error) {
	_ = entryToken // Подавляет предупреждение о неиспользуемом параметре

	return &models.User{
		Email: "user@example.com",
		Roles: []string{"user"},
	}, nil
}

// Обработчик для авторизации через Яндекс
func YandexAuthHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "yandex_login.html", nil)
}

// Обработчик для авторизации через GitHub
func GithubAuthHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "github_login.html", nil)
}

// Обработчик для страницы запроса кода
func RequestCodeForm(c *gin.Context) {
	c.HTML(http.StatusOK, "request_code.html", nil)
}

// Обработчик для начала авторизации через Яндекс
func YandexLoginHandler(c *gin.Context) {
	authURL := "https://oauth.yandex.ru/authorize"
	clientID := os.Getenv("YANDEX_CLIENT_ID")
	redirectURI := "https://535c-195-93-160-12.ngrok-free.app/yandex/callback" // Убедитесь, что совпадает

	loginURL := authURL + "?response_type=code&client_id=" + clientID + "&redirect_uri=" + redirectURI
	c.Redirect(http.StatusFound, loginURL)
}

// Обработчик авторизации через Яндекс
func YandexCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	accessToken, err := auth.HandleYandexCallback(c, code)
	if err != nil {
		log.Printf("Ошибка авторизации: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate"})
		return
	}

	// Сохраняем токен в cookie
	c.SetCookie("Authorization", accessToken, 3600, "/", "535c-195-93-160-12.ngrok-free.app", false, true)

	// Перенаправляем на защищённый маршрут
	c.Redirect(http.StatusFound, "/protected")
}

func LoginHandler(c *gin.Context) {
	sessionToken, err := c.Cookie("session_token")
	if err != nil {
		// Новый пользователь — создаём токен сессии
		sessionToken = auth.GenerateSessionToken()
		if sessionToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session token"})
			return
		}

		// Сохраняем токен в куки
		c.SetCookie("session_token", sessionToken, 3600, "/", "", false, true)

		// Устанавливаем статус Unknown
		err := auth.SetUserStatus(sessionToken, "Unknown")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set user status"})
			return
		}

		// Редирект на главную
		c.Redirect(http.StatusFound, "/")
		return
	}

	// Логика для существующего токена
	status, err := auth.GetUserStatus(sessionToken)
	if err != nil || status == "" {
		// Токен не найден или статус не задан
		auth.SetUserStatus(sessionToken, "Unknown")
		c.Redirect(http.StatusFound, "/")
		return
	}

	if status == "Authorized" {
		c.Redirect(http.StatusFound, "/protected")
		return
	}

	// Если пользователь анонимный, показываем форму входа
	c.HTML(http.StatusOK, "login.html", nil)
}

func RefreshHandler(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
		return
	}

	accessToken, newRefreshToken, err := auth.RefreshAccessToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

func AuthMiddleware(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		c.Abort()
		return
	}

	claims, err := auth.ParseToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired access token"})
		c.Abort()
		return
	}

	c.Set("email", claims.Email)
	c.Set("roles", claims.Roles)
	c.Next()
}

func ProtectedHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
		c.JSON(401, gin.H{"error": "missing or invalid token"})
		return
	}

	tokenString := authHeader[7:]
	secretKey := os.Getenv("JWT_SECRET_KEY")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}

	c.JSON(200, gin.H{"message": "access granted"})
}

func GitHubLoginHandler(c *gin.Context) {
	clientID := os.Getenv("GITHUB_CLIENT_ID") // Читаем GitHub Client ID из переменных окружения
	redirectURI := "http://localhost:8080/github/callback"

	// Создаем URL для авторизации
	authURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email", clientID, redirectURI)
	c.Redirect(http.StatusFound, authURL)
}

func GitHubCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not provided"})
		return
	}

	// Шаг 1. Обмен кода на токен
	token, err := exchangeCodeForToken(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Шаг 2. Получение данных пользователя
	email, err := fetchGitHubUserEmail(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Шаг 3. Проверка и создание пользователя в MongoDB
	ctx := context.TODO()
	user, err := database.FindUserByEmail(ctx, email)
	if err != nil && err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if user == nil {
		newUser := &models.User{
			Email: email,
			Roles: []string{"student"},
		}
		if err := database.CreateUser(ctx, newUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	}

	// Шаг 4. Создание JWT-токена
	accessToken, err := auth.CreateToken(email, []string{"student"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Authorized successfully",
		"access_token": accessToken,
	})
}

// exchangeCodeForToken — обмен кода на токен
func exchangeCodeForToken(code string) (string, error) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)

	resp, err := http.PostForm("https://github.com/login/oauth/access_token", data)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code for token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to exchange code for token, status: %d, response: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	return result.AccessToken, nil
}

// fetchGitHubUserEmail — получает email пользователя из GitHub
func fetchGitHubUserEmail(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user email: %v", err)
	}
	defer resp.Body.Close()

	// Выводим весь ответ от GitHub для анализа
	body, _ := io.ReadAll(resp.Body)
	log.Printf("GitHub API response: %s", body)

	// Декодируем как массив email-ов
	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("failed to decode email response: %v", err)
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", errors.New("no email found")
}

func generateCode() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func RequestCodeHandler(c *gin.Context) {

	var requestData struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&requestData); err != nil {
		log.Println("Ошибка привязки JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	email := requestData.Email
	if email == "" {
		log.Println("Email not provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	log.Printf("Получен email: %s\n", email)

	// Генерация кода
	code := generateCode()

	// Сохранение кода в Redis
	err := auth.SetCache(email, code)
	if err != nil {
		log.Printf("Ошибка работы с Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save code"})
		return
	}

	// Отправка email
	err = auth.SendEmail(email, code)
	if err != nil {
		log.Printf("Ошибка отправки email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	err = auth.SendEmail(email, code)
	if err != nil {
		log.Printf("Ошибка отправки email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}
	log.Println("Email успешно отправлен")

	c.JSON(http.StatusOK, gin.H{"message": "Code sent to your email"})

	c.JSON(http.StatusOK, gin.H{"message": "Code sent to your email"})
}

// Обработчик для проверки кода
func VerifyCodeHandler(c *gin.Context) {
	ctx := context.Background()
	email := c.PostForm("email")
	code := c.PostForm("code")

	if email == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and code are required"})
		return
	}

	// Проверка кода из Redis
	storedCode, err := redisClient.Get(ctx, email).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Code expired or not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check code"})
		return
	}

	// Сравнение введённого кода с сохранённым
	if storedCode != code {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid code"})
		return
	}

	// Успешная проверка
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

var redisClient *redis.Client

func SetRedisClient(client *redis.Client) {
	redisClient = client
}

// Обработчик для рендера страницы создания тестов
func CreateTestPage(c *gin.Context) {
	c.HTML(http.StatusOK, "create_test.html", nil)
}

// Обработчик для обработки отправки тестов
func SubmitTestHandler(c *gin.Context) {
	var requestBody struct {
		TestName  string   `json:"testName"`
		Questions []string `json:"questions"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Сохранение теста в базе данных
	err := database.SaveTest(requestBody.TestName, requestBody.Questions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save test"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test created successfully"})
}
