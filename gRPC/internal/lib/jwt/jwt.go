package jwt

import (
	"time"
	"todo-grpc/internal/domain/models"

	"github.com/dgrijalva/jwt-go"
)

type TokenClaims struct {
	jwt.StandardClaims
	Email string `json:"email"`
	Uid   int64  `json:"uid"`
	AppID int    `json:"app_id"`
}

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		Email: user.Email,
		Uid:   user.ID,
		AppID: app.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(duration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})

	return token.SignedString([]byte(app.Secret))
}
