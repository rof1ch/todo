package tests

import (
	"fmt"
	"testing"
	"time"
	"todo-grpc/tests/suite"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/dgrijalva/jwt-go"
	ssov1 "github.com/rof1ch/todo-proto/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

type TokenClaims struct {
	jwt.StandardClaims
	Email string `json:"email"`
	Uid   int64  `json:"uid"`
	AppID int    `json:"app_id"`
}

func (t *TokenClaims) Valid() error {
	// Проверяем стандартные claims (например, истечение срока действия)
	if err := t.StandardClaims.Valid(); err != nil {
		return err
	}

	// Дополнительные проверки, если необходимо
	if t.Uid <= 0 {
		return fmt.Errorf("invalid UID: %d", t.Uid)
	}

	if t.AppID <= 0 {
		return fmt.Errorf("invalid AppID: %d", t.AppID)
	}

	return nil
}

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.ParseWithClaims(token, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	fmt.Println(tokenParsed.Claims)
	claims, ok := tokenParsed.Claims.(*TokenClaims)
	assert.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), claims.Uid)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, appID, claims.AppID)

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims.ExpiresAt, deltaSeconds)
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
