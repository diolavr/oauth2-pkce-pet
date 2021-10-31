package main

import (
	"crypto/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	log "github.com/sirupsen/logrus"
)

const (
	AccessTokenExpire  = time.Hour * 24 * 7
	RefreshTokenExpire = time.Hour * 24 * 30
)

var oauthServer *server.Server //nolint:gochecknoglobals

func NewOAuth2ClientStore() *store.ClientStore {
	clientStore := store.NewClientStore()
	_ = clientStore.Set("Application.ID", &models.Client{
		ID:     "Application.ID",
		Secret: "Application.Secret",
	})

	return clientStore
}

func NewJWTGenerator() *generates.JWTAccessGenerate {
	const SignedKeyIDLength = 16

	var SignedKey = []byte("signed-key")

	SignedKeyID := make([]byte, SignedKeyIDLength)
	_, _ = rand.Read(SignedKeyID)

	return generates.NewJWTAccessGenerate(
		string(SignedKeyID),
		SignedKey,
		jwt.SigningMethodHS512,
	)
}

func NewOAuth2Manager() *manage.Manager {
	m := manage.NewDefaultManager()
	// Хранилище пользователей
	m.MapClientStorage(NewOAuth2ClientStore())
	// Генератор токенов
	m.MapAccessGenerate(NewJWTGenerator())
	// Токены пока в памяти сохраним
	m.MustTokenStorage(store.NewMemoryTokenStore())
	// Время хранения токенов
	m.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    AccessTokenExpire,
		RefreshTokenExp:   RefreshTokenExpire,
		IsGenerateRefresh: true,
	})

	return m
}

func NewOAuth2Server() *server.Server {
	s := server.NewDefaultServer(NewOAuth2Manager())
	s.SetAllowGetAccessRequest(true)

	// Обработчики
	s.SetClientInfoHandler(server.ClientFormHandler)
	s.SetUserAuthorizationHandler(OAuth2UserAuthorizationHandler)
	s.SetInternalErrorHandler(OAuth2InternalErrorHandler)
	s.SetResponseErrorHandler(OAuth2ResponseErrorHandler)

	oauthServer = s

	return s
}

func OAuth2UserAuthorizationHandler(w http.ResponseWriter, req *http.Request) (userID string, err error) {
	store, err := session.Start(req.Context(), w, req)
	if err != nil {
		return "", err
	}

	uid, ok := store.Get(LoggedInUserID)
	if !ok {
		if req.Form == nil {
			_ = req.ParseForm()
		}

		store.Set(StorageKeyReturURI, req.Form)
		_ = store.Save()

		w.Header().Set("Location", "/oauth2/authenticate")
		w.WriteHeader(http.StatusFound)

		return
	}

	userID = uid.(string)

	store.Delete(LoggedInUserID)
	_ = store.Save()

	return userID, nil
}

func OAuth2InternalErrorHandler(err error) (re *errors.Response) {
	log.Error(err)
	return
}

func OAuth2ResponseErrorHandler(re *errors.Response) {
	log.Error(re.Error)
}
