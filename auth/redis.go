package auth

import (
	"fmt"
	"log"
	"os"

	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
)

var rdb *redis.Client

// Инициализация Redis
func InitRedis() error {
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"), // Адрес Redis сервера
		Password: "",                      // Нет пароля (по умолчанию)
		DB:       0,                       // Используем 0-й БД
	})

	_, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		return fmt.Errorf("Error connecting to Redis: %v", err)
	}

	return nil
}

// Функция для хранения данных в Redis
func SetCache(key string, value string) error {
	err := rdb.Set(context.Background(), key, value, 0).Err()
	if err != nil {
		log.Printf("Error setting cache: %v", err)
		return err
	}
	return nil
}

