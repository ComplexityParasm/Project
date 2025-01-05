package models

// User — структура для хранения данных пользователя.
type User struct {
	FullName string   `json:"full_name" bson:"full_name"`
	Email    string   `json:"email" bson:"email"`
	Password string   `json:"password,omitempty" bson:"password,omitempty"`
	Roles    []string `json:"roles" bson:"roles"`
}
