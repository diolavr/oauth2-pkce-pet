package main

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session"
	log "github.com/sirupsen/logrus"
)

const LoggedInUserID = "LoggedInUserID"
const StorageKeyReturURI = "ReturnUri"

func AuthorizeAny(c *gin.Context) {
	/*
		Авторизация пользователя
		Вызывается пользователем как часть потока авторизации
	*/
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodPost {
		c.AbortWithStatus(http.StatusBadRequest)

		return
	}

	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	if v, ok := store.Get(StorageKeyReturURI); ok {
		c.Request.Form = v.(url.Values)
	}

	store.Delete(StorageKeyReturURI)
	_ = store.Save()

	if err := oauthServer.HandleAuthorizeRequest(c.Writer, c.Request); err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusBadRequest)

		return
	}
}

func AuthenticateGet(c *gin.Context) {
	/*
		Должна быть форма авторизации куда вводятся username и password.
		Роут сообщает о том, что аутентификация обязательна и все данные нужно отправить на POST /oauth2/authenticate
	*/
	c.JSON(http.StatusOK, map[string]string{"action": "/oauth2/authenticate", "method": "POST"})
}

func AuthenticatePost(c *gin.Context) {
	/*
		Фактическая аутентификация пользователя.

		Проверяется username и password и все такое по списку.
		По окончании произойдет перенаправление на индентификацию

		Вызывается пользователем как часть потока авторизации

		Сюда перенаправляют роуты:
		- GET /oauth2/identicate когда не удалось идентифицировать пользователя
	*/
	store, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	if c.Request.Form == nil {
		if err := c.Request.ParseForm(); err != nil {
			log.Error(err)
			c.AbortWithStatus(http.StatusInternalServerError)

			return
		}
	}

	un := c.Request.Form.Get("username")
	if un == "" {
		log.Error("Empty `username` field")
		c.AbortWithStatus(http.StatusPaymentRequired)

		return
	}

	store.Set(LoggedInUserID, un)
	_ = store.Save()

	// Перенаправление на индентификацию
	// Аутентификация теперь должна быть подтверждена
	c.Writer.Header().Set("Location", "/oauth2/identicate")
	c.Status(http.StatusFound)
}

func IdenticateGet(c *gin.Context) {
	/*
		Идентификация. Проверяем что мы узнаём того кто к нам пришел.

		Сюда перенаправляют роуты:
		- POST /oauth2/authenticate после аутентификации пользователя
	*/
	store, err := session.Start(nil, c.Writer, c.Request) //nolint:staticcheck
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	if _, ok := store.Get(LoggedInUserID); !ok {
		// Неизвестно кто пришел, перенаправляем на GET /oauth2/authenticate
		c.Writer.Header().Set("Location", "/oauth2/authenticate")
		c.Status(http.StatusFound)

		return
	}

	/*
		Должна быть отрисовка формы для подтверждения пользователем предоставления доступов к своим учетным данным на сервере.
		Отправка данных с формы POST /oauth2/authorize. Но у меня другие планы
	*/
	c.JSON(http.StatusOK, map[string]string{"action": "/oauth2/authorize", "method": "POST"})
}

func TokenGet(c *gin.Context) {
	/*
		Получение токена авторизации

		Вызывается пользователем как часть потока авторизации
	*/
	err := oauthServer.HandleTokenRequest(c.Writer, c.Request)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)

		return
	}
}
