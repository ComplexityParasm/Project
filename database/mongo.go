package database

import (
	"context"
	"fmt"
	"go-auth/models"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client
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

	// Получаем имя базы данных и коллекции из переменных окружения
	dbName := os.Getenv("MONGO_DB_NAME")
	collectionName := os.Getenv("MONGO_COLLECTION_NAME")
	usersCollection = client.Database(dbName).Collection(collectionName)

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

func CreateUser(ctx context.Context, user *models.User) error {
	_, err := usersCollection.InsertOne(ctx, user)
	if err != nil {
		log.Printf("Ошибка добавления пользователя в MongoDB: %v", err)
		return err
	}
	return nil
}

var TestCollection *mongo.Collection

func InitTestCollection(dbName string) {
	TestCollection = client.Database(dbName).Collection("tests")
}

// SaveTest сохраняет тест в коллекцию MongoDB
func SaveTest(testName string, questions []string) error {
	collection := mongoClient.Database("your_database_name").Collection("tests")

	testDocument := bson.M{
		"testName":  testName,
		"questions": questions,
	}

	_, err := collection.InsertOne(context.TODO(), testDocument)
	if err != nil {
		log.Printf("Ошибка при сохранении теста: %v", err)
		return err
	}

	log.Println("Тест успешно сохранен:", testName)
	return nil
}
