package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"
)

/*
https://auth0.com/docs/authorization/flows/authorization-code-flow
*/

func TestClient(t *testing.T) {
	const authServerURL = "http://localhost:8080"
	config := oauth2.Config{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		Scopes:       []string{"all"},
		RedirectURL:  authServerURL + "/account",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/oauth/authorize",
			TokenURL: authServerURL + "/oauth/token",
		},
	}

	jar, _ := cookiejar.New(nil)
	client := http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	{
		// Authorization request
		u := config.AuthCodeURL("randomState",
			oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		resp, err := client.Get(u)
		require.NoError(t, err)
		defer resp.Body.Close()

		url, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, "/login", url.Path)
	}
	{
		// Get login page
		resp, err := client.Get(authServerURL + "/login")
		require.NoError(t, err)
		defer resp.Body.Close()

		b, _ := ioutil.ReadAll(resp.Body)
		assert.Equal(t, string(b), "login page")
	}
	{
		// Simulate clicking login button
		resp, err := client.Post(
			authServerURL+"/login",
			"application/json",
			bytes.NewBufferString(`{"User": "test", "Password": "test"}`),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		url, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, "/oauth/authorize", url.Path)
	}
	var token *oauth2.Token
	{
		// Get token
		resp, err := client.Get(authServerURL + "/oauth/authorize")
		require.NoError(t, err)
		defer resp.Body.Close()
		url, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, "randomState", url.Query().Get("state"))
		code := url.Query().Get("code")
		assert.NotEmpty(t, code)

		token, err = config.Exchange(
			context.Background(),
			code,
			oauth2.SetAuthURLParam("code_verifier", "s256example"),
		)
		require.NoError(t, err)
	}
	{
		// Access protected resource
		// This client automatically refreshes the token when needed
		tokenClient := config.Client(context.Background(), token)
		resp, err := tokenClient.Get(authServerURL + "/protected")
		require.NoError(t, err)
		defer resp.Body.Close()

		b, _ := ioutil.ReadAll(resp.Body)
		assert.Equal(t, string(b), "a protected resource")
	}
	{
		// Refresh the token
		oldToken := token
		token.Expiry = time.Now() // Expire the token
		newToken, err := config.TokenSource(context.Background(), token).Token()
		require.NoError(t, err)
		// The access token changed
		assert.NotEqual(t, oldToken.AccessToken, newToken.AccessToken)
	}
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}
