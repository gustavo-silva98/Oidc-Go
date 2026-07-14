package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		log.Printf("Failed to load Config Parameters: %v", err)
		return
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.issuerURL)
	if err != nil {
		log.Printf("Failed to initialize OIDC provider: %v", err)
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
	fmt.Fprintf(w, `<html><body><a href="/login"> Click here to logon! </a></body></html>`)
}

func handleLoginOk(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body> Login Successful! </body></html>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := createRandomString(32)
	if err != nil {
		log.Printf("Failed to generate State: %v", err)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	nonce, err := createRandomString(32)
	if err != nil {
		log.Printf("Failed to generate Nonce: %v", err)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	codeVerifier := oauth2.GenerateVerifier() // Generate PKCE Code
	log.Println("STEP 1: State, Nonce and PKCE code generated.")

	// Secure Parameter is missing because this is a tutorial. In production, use Secure/TLS when setting a cookie
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
	http.SetCookie(w, &http.Cookie{
		Name:     "codeVerifier",
		Value:    codeVerifier,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	redirectUrl := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(codeVerifier))
	log.Println("STEP 1: Nonce, State and PKCE are set as a cookie in the browser.")
	log.Println("STEP 2: User will be redirected to MS Auth page")
	log.Printf("Redirect URL: %v", redirectUrl)
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie("state")
	if err != nil {
		log.Printf("Failed to extract state value from cookie")
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	nonce, err := r.Cookie("nonce")
	if err != nil {
		log.Printf("Falha ao achar o cookie nonce")
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	code_verifier, err := r.Cookie("codeVerifier")
	if err != nil {
		log.Printf("Failed to extract PKCE code value from cookie")
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	log.Println("STEP 3: Cookie values from state, nonce and PKCE has been extracted!")

	if r.URL.Query().Get("state") != state.Value {
		log.Printf("Failed to validate State Value. Val. Exp: %v - Val. Received: %v", state, r.URL.Query().Get("state"))
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	log.Println("STEP 3: State validation has been succeed!")

	ctx := r.Context()
	token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(code_verifier.Value))
	if err != nil {
		log.Printf("Failed to perform token Exchange: %v", err)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	log.Println("STEP 4: Exchange code for token has been succeed!")
	log.Printf("STEP 4: AccessToken Lenght: %v", len(token.AccessToken))

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Print("Id_token is missing in token received")
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}

	idtoken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Fail on Id_Token verification: %v", err)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	log.Println("STEP 5: ID_Token verification by oidc package (signature, issuer, aud) has been succeed!")

	var claims struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Sub    string   `json:"sub"`
		Tid    string   `json:"tid"`
		Oid    string   `json:"oid"`
		Aud    string   `json:"aud"`
		Nonce  string   `json:"nonce"`
		Groups []string `json:"groups"` // Claim that you can use to build authorization based on security groups
	}

	if err := idtoken.Claims(&claims); err != nil {
		log.Printf("Error parsing id_token claims: %v", err)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}

	if nonce.Value != claims.Nonce {
		log.Printf("Failed to validate Nonce. Val. Exp: %v - Val. Received: %v", nonce.Value, claims.Nonce)
		http.Error(w, "Failed to authenticate user", http.StatusInternalServerError)
		return
	}
	log.Println("STEP 5: Nonce value has been succeed!")

	response, _ := json.MarshalIndent(claims, "", " ")

	log.Println("STEP 5: ID_TOKEN claims below. Use this to build your session management")
	log.Println(string(response))

	// Cookie invalidations
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // MaxAge <0 means that the cookie will be deleted
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "nonce",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // MaxAge <0 means that the cookie will be deleted
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "codeVerifier",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // MaxAge <0 means that the cookie will be deleted
	})
	log.Println("STEP 5: Cookies PKCE code, nonce and state deleted from the browser.")
	log.Println("STEP 5: Redirecting user to happy path. /login-ok route.")
	http.Redirect(w, r, "/login-ok", http.StatusFound)

}

func createRandomString(n int) (string, error) {
	s := make([]byte, n)
	if _, err := rand.Read(s); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(s), nil
}
