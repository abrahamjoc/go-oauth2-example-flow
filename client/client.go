package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const authServerURL = "http://localhost:9096"

var (
	clientPort   = 9094
	clientConfig = oauth2.Config{
		ClientID:     "10b4b65c-51b0-4fa8-bcd9-374746d2ca43",
		ClientSecret: "kDzYVsMleZ",
		Scopes: []string{
			"read",
		},
		RedirectURL: fmt.Sprintf("http://localhost:%d/callback", clientPort),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/oauth/authorize",
			TokenURL: authServerURL + "/oauth/token",
		},
	}
	clientState   = randomStr(8)
	clientToken   *oauth2.Token
	codeVerifier  string
	codeChallenge string
)

func main() {
	// Authorization Code Grant Flow
	http.HandleFunc("/code", func(w http.ResponseWriter, r *http.Request) {
		oAuth2Client := newOAuth2Client()
		codeVerifier = genCodeVerifier()
		codeChallenge = genCodeChallengeS256(codeVerifier)
		u := oAuth2Client.AuthCodeURL(clientState,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, u, http.StatusFound)
	})

	// Authorization Code Grant Callback
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		state := r.Form.Get("state")
		if state != clientState {
			http.Error(w, "State invalid", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		oAuth2Client := newOAuth2Client()
		token, err := oAuth2Client.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		clientToken = token
		jsonResponse(w, token)
	})

	// Client Credentials Grant Flow
	http.HandleFunc("/client-credentials", func(w http.ResponseWriter, r *http.Request) {
		oAuth2Client := clientcredentials.Config{
			ClientID:     clientConfig.ClientID,
			ClientSecret: clientConfig.ClientSecret,
			TokenURL:     clientConfig.Endpoint.TokenURL,
		}

		token, err := oAuth2Client.Token(context.Background())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		clientToken = token
		jsonResponse(w, token)
	})

	// Password Credentials Grant Flow
	http.HandleFunc("/pwd-credentials", func(w http.ResponseWriter, r *http.Request) {
		oAuth2Client := newOAuth2Client()
		token, err := oAuth2Client.PasswordCredentialsToken(context.Background(), "test", "test")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		clientToken = token
		jsonResponse(w, token)
	})

	// Refresh Token Grant Flow
	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if clientToken == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		oAuth2Client := newOAuth2Client()
		clientToken.Expiry = time.Now()
		token, err := oAuth2Client.TokenSource(context.Background(), clientToken).Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		clientToken = token
		jsonResponse(w, token)
	})

	// Let's try to consume protected resources
	http.HandleFunc("/resource-protected", func(w http.ResponseWriter, r *http.Request) {
		if clientToken == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		resp, err := http.Get(fmt.Sprintf("%s/resource-protected-with-token?access_token=%s", authServerURL, clientToken.AccessToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		_, _ = io.Copy(w, resp.Body)
	})

	// Default Grant Flow
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/code", http.StatusPermanentRedirect)
	})

	// Running Client
	log.Println(fmt.Sprintf("Client is running at %d port.Please open http://localhost:%d/", clientPort, clientPort))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", clientPort), nil))
}

// Util functions
func newOAuth2Client() oauth2.Config {
	return oauth2.Config{
		ClientID:     clientConfig.ClientID,
		ClientSecret: clientConfig.ClientSecret,
		Scopes:       clientConfig.Scopes,
		RedirectURL:  clientConfig.RedirectURL,
		Endpoint:     clientConfig.Endpoint,
	}
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomStr(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func base64Encode(data []byte) string {
	s := base64.URLEncoding.EncodeToString(data)
	return strings.ReplaceAll(s, "=", "")
}

func genCodeVerifier() string {
	str := randomStr(32)
	return base64Encode([]byte(str))
}

func genCodeChallengeS256(codeVerifier string) string {
	s256 := sha256.Sum256([]byte(codeVerifier))
	return base64Encode(s256[:])
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	_ = e.Encode(data)
}
