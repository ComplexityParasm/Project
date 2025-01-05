package auth

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// Middleware для проверки JWT-токена
func AuthMiddleware(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Попытка получить токен из заголовка Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Если заголовок отсутствует, попытка получить токен из cookie
			tokenCookie, err := c.Cookie("Authorization")
			if err != nil {
				log.Println("Authorization token missing in header and cookie")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
				c.Abort()
				return
			}
			authHeader = "Bearer " + tokenCookie
		}

		// Проверяем формат "Bearer <token>"
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			log.Println("Invalid Authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		// Получаем сам токен
		tokenString := tokenParts[1]

		// Парсим токен и валидируем его
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Проверяем, что токен использует правильный метод подписи
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
			}
			return []byte(secretKey), nil
		})

		if err != nil {
			log.Printf("Error parsing token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Проверяем, валиден ли токен
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Передаем email и роли в контекст Gin
			c.Set("email", claims["email"])
			c.Set("roles", claims["roles"])
		} else {
			log.Println("Token is not valid")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Логирование заголовка и cookie для отладки
		log.Println("Authorization Header:", authHeader)

		// Если всё в порядке, передаем управление следующему обработчику
		c.Next()
	}
}
