package main

import (
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"log"
	"net/http"
	"net/url"
)

/*
https://auth0.com/docs/authorization/flows/authorization-code-flow
Not secure for web apps; should use PKCE
*/
const parametersField = "parameters"
const userIDField = "userID"

func main() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	clientStore.Set("clientID", &models.Client{
		ID:     "clientID",
		Secret: "clientSecret",
		Domain: "http://localhost:8080",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetPasswordAuthorizationHandler(func(username, password string) (string, error) {
		if username == "test" && password == "test" {
			return "userID", nil
		}
		return "", errors.ErrAccessDenied
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	router := gin.Default()
	router.GET("/oauth/authorize", func(c *gin.Context) {
		state, err := session.Start(c, c.Writer, c.Request)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		var form url.Values
		if v, ok := state.Get(parametersField); ok {
			form = v.(url.Values)
		}
		c.Request.Form = form

		state.Delete(parametersField)
		state.Save()

		if err := srv.HandleAuthorizeRequest(c.Writer, c.Request); err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
		}
	})

	router.GET("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "login page")
	})

	router.POST("/login", func(c *gin.Context) {
		requestBody := struct {
			User     string
			Password string
		}{}
		c.BindJSON(&requestBody)
		if requestBody.User == "test" && requestBody.Password == "test" {
			state, err := session.Start(c, c.Writer, c.Request)
			if err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			state.Set(userIDField, requestBody.User)
			state.Save()

			c.Redirect(http.StatusSeeOther, "/oauth/authorize")
		} else {
			c.Status(http.StatusUnauthorized)
		}
	})

	router.POST("/oauth/token", func(c *gin.Context) {
		if err := srv.HandleTokenRequest(c.Writer, c.Request); err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}
	})

	router.GET("/protected", func(c *gin.Context) {
		// A protected resource
		tokenInfo, err := srv.ValidationBearerToken(c.Request)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
		}
		// User must be "test"
		// Typically, a database is used to look up the user
		if tokenInfo.GetUserID() != "test" {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.String(http.StatusOK, "a protected resource")
	})

	if err := router.Run(":8080"); err != nil {
		log.Println(err)
	}
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := session.Start(r.Context(), w, r)
	if err != nil {
		return "", err
	}
	state.Set(parametersField, r.Form)

	uid, ok := state.Get(userIDField)
	if ok {
		state.Delete(userIDField)
		state.Save()
		return uid.(string), nil
	}

	r.ParseForm()
	state.Set(parametersField, r.Form)
	state.Save()

	http.Redirect(w, r, "/login", http.StatusFound)
	return "", nil
}
