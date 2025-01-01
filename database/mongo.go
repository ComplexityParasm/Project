package database

import (
	"context"
	"fmt"

	"go-auth/models"
	//"log"
	//"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var usersCollection *mongo.Collection

// Инициализация подключения к базе данных MongoDB
func InitMongoDB(mongoURI string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	c, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	client = c
	usersCollection = client.Database("auth_db").Collection("users")
	return nil
}

// Функция для поиска пользователя по email
func FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{"email": email}
	err := usersCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Функция для добавления нового пользователя в MongoDB
func CreateUser(ctx context.Context, user *models.User) error {
	_, err := usersCollection.InsertOne(ctx, user)
	return err
}
