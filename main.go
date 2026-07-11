package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

func main() {
	config, err := loadConfigParameters()
	if err != nil {
		log.Printf("Falha ao carregar parametros config: %v", err)
		return
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.issuerURL)
	if err != nil {
		log.Printf("Falha ao inicializar OIDC provider: %v", err)
		return
	}

	oauth2Config = &oauth2.Config{
		ClientID:     config.clientID,
		ClientSecret: config.clientSecret,
		RedirectURL:  config.redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: config.clientID})
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/login-ok", handleLoginOk)

	fmt.Println("Server running: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body><a href="/login"> Clique para logar! </a></body></html>`)
}

func handleLoginOk(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body> Login Bem Sucedido! </body></html>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := createRandomString(32)
	if err != nil {
		log.Printf("Falha na criação de State: %v", err)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}
	nonce, err := createRandomString(32)
	if err != nil {
		log.Printf("Falha na criação de State: %v", err)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie("state")
	if err != nil {
		log.Printf("Falha ao achar o cookie")
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		log.Printf("Falha na validação de State. Val. Esperado: %v - Val. recebido: %v", state, r.URL.Query().Get("state"))
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("Falha na troca de token Exchange: %v", err)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Print("Sem id_token na resposta")
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}
	idtoken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Falha na verificação do ID Token: %v", err)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email     string   `json:"email"`
		Name      string   `json:"name"`
		Sub       string   `json:"sub"`
		Tid       string   `json:"tid"`
		Oid       string   `json:"oid"`
		Aud       string   `json:"aud"`
		Idp       string   `json:"idp"`
		Iat       int      `json:"iat"`
		Exp       int      `json:"exp"`
		Nonce     string   `json:"nonce"`
		UPN       string   `json:"upn"`
		Sid       string   `json:"sid"` //Session ID
		HasGroups bool     `json:"hasgroups"`
		Groups    []string `json:"groups"`
	}

	if err := idtoken.Claims(&claims); err != nil {
		log.Printf("Erro ao parsear claims: %v", err)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		log.Printf("Falha ao achar o cookie")
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}

	if nonce.Value != claims.Nonce {
		log.Printf("Falha ao validar Nonce. Val. Esperado: %v - Val. Recebido: %v", nonce.Value, claims.Nonce)
		http.Error(w, "Falha na autenticação", http.StatusInternalServerError)
		return
	}

	//response, _ := json.MarshalIndent(claims, "", " ")
	//w.Header().Set("Content-Type", "application/json")
	//w.Write(response)

	// Invalidando cookie de state e nonce
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
		MaxAge:   -1, // Parametro <0 significa deleção de cookie
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "nonce",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
		MaxAge:   -1, // Parametro <0 significa deleção de cookie
	})
	http.Redirect(w, r, "/login-ok", http.StatusFound)

}

func createRandomString(n int) (string, error) {
	s := make([]byte, n)
	if _, err := rand.Read(s); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(s), nil
}
