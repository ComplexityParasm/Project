package models

// User — структура для хранения данных пользователя.
type User struct {
	Email    string   `json:"email" bson:"email"`
	Password string   `json:"password" bson:"password"`
	Roles    []string `json:"roles" bson:"roles"`
}
