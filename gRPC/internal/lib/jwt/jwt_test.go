package jwt

import (
	"fmt"
	"testing"
	"time"
	"todo-grpc/internal/domain/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	user := models.User{
		ID:    123,
		Email: "test@test.com",
	}

	app := models.App{
		ID:     123321,
		Secret: "secret0asdasiodunaisdnahsdbjahsdbjhabs",
	}

	token, err := NewToken(user, app, time.Hour)
	assert.Nil(t, err)

	claims, err := ParseToken(token, app.Secret)
	assert.Equal(t, user.ID, claims.Uid)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, app.ID, claims.AppID)
}

func ParseToken(tokenString string, secret string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем, что используется правильный метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	// Проверяем, что токен валиден и содержит наши кастомные claims
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
