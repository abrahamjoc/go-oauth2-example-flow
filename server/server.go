package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"github.com/kr/pretty"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

var (
	staticClient = struct {
		ClientId     string
		ClientSecret string
		ClientDomain string
	}{
		"10b4b65c-51b0-4fa8-bcd9-374746d2ca43",
		"kDzYVsMleZ",
		"http://localhost:9094",
	}

	userExample = struct {
		UserId   string
		Username string
		Password string
	}{
		"ebdd025f-a81d-473f-bcc1-9acfe10c70e2",
		"test",
		"test",
	}

	serverPort = 9096
	srv        *server.Server
)

func main() {
	log.Print("OAuth2 Server Example Flow.")
	log.Printf("Client UserId              = %s\n", userExample.UserId)
	log.Printf("Client Username / Password = %s / %s\n", userExample.Username, userExample.Password)

	//
	// OAuth2 Manager Configuration
	// =================================================================================================================
	manager := manage.NewDefaultManager()

	// Token Store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// Access Token Generator
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	// Clients Configuration
	clientStore := store.NewClientStore()
	clientStore.Set(staticClient.ClientId, &models.Client{
		ID:     staticClient.ClientId,
		Secret: staticClient.ClientSecret,
		Domain: staticClient.ClientDomain,
	})
	manager.MapClientStorage(clientStore)

	// Set Default Token Grants Configuration
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.SetPasswordTokenCfg(manage.DefaultPasswordTokenCfg)
	manager.SetClientTokenCfg(manage.DefaultClientTokenCfg)

	//
	// OAuth2 Server Configuration
	// =================================================================================================================
	oauth2ServerConfig := server.Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
		ForcePKCE: true,
	}
	srv = server.NewServer(&oauth2ServerConfig, manager)

	// Set User Authorization Handlers
	srv.SetUserAuthorizationHandler(userAuthorizationCodeHandler)
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, username, password string) (userID string, err error) {
		if username == userExample.Username && password == userExample.Password {
			userID = userExample.UserId
		}
		return
	})

	// OAuth2 Server Endpoints
	http.HandleFunc("/login", loginServerHandler)
	http.HandleFunc("/auth", authServerHandler)
	http.HandleFunc("/oauth/authorize", authorizeServerHandler)
	http.HandleFunc("/oauth/token", tokenServerHandler)

	// Business Resource Protected
	http.HandleFunc("/resource-protected-with-token", resourceProtectedWithTokenHandler)

	// Running Server
	log.Printf("Server is running in port  = %d", serverPort)
	log.Printf("Server Auth  endpoint      = %s:%d%s", "http://localhost", serverPort, "/oauth/authorize")
	log.Printf("Server Token endpoint      = %s:%d%s", "http://localhost", serverPort, "/oauth/token")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil))
}

// OAuth2 endpoint handlers
func loginServerHandler(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest("login", r)

	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		outputHTML(w, r, "static/login.html")
	}

	if r.Method == http.MethodPost {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		if username != userExample.Username || password != userExample.Password {
			http.Error(w, "User credentials are wrong", http.StatusBadRequest)
			return
		}

		store.Set("LoggedUserSession", userExample.UserId)
		store.Save()

		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
		return
	}
}

func authServerHandler(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest("auth", r)

	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedUserSession"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func authorizeServerHandler(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest("authorizeServerHandler", r)

	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if v, ok := store.Get("OAuth2Params"); ok {
		r.Form = v.(url.Values)
		_, _ = pretty.Println(r.Form)
		store.Delete("OAuth2Params")
		store.Save()
	}

	err = srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func userAuthorizationCodeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	_ = dumpRequest("userAuthorizationCodeHandler", r)

	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedUserSession")
	if !ok {
		_, _ = pretty.Println(r.Form)
		store.Set("OAuth2Params", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedUserSession")
	store.Save()
	return
}

func tokenServerHandler(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest("token", r)

	err := srv.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Business server handler
func resourceProtectedWithTokenHandler(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest("resourceProtected", r)

	token, err := srv.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := map[string]interface{}{
		"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		"client_id":  token.GetClientID(),
		"user_id":    token.GetUserID(),
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	_ = e.Encode(data)
}

// Util functions
func dumpRequest(header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer := os.Stdout
	_, _ = writer.Write([]byte("\n" + header + ": \n"))
	_, _ = writer.Write(data)
	return nil
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		filename = "./server/" + filename
	}
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}
