package models

type Test struct {
	Name      string   `json:"name" bson:"name"`
	Questions []string `json:"questions" bson:"questions"`
}
