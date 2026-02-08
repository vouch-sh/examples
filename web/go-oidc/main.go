package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	verifier     *oidc.IDTokenVerifier
)

type sessionData struct {
	Email            string `json:"email"`
	HardwareVerified bool   `json:"hardware_verified"`
}

// Simple in-memory session store (use a proper store in production)
var sessions = map[string]*sessionData{}
var states = map[string]bool{}

func main() {
	issuer := os.Getenv("VOUCH_ISSUER")
	if issuer == "" {
		issuer = "https://us.vouch.sh"
	}
	clientID := os.Getenv("VOUCH_CLIENT_ID")
	clientSecret := os.Getenv("VOUCH_CLIENT_SECRET")
	redirectURI := os.Getenv("VOUCH_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://localhost:3000/callback"
	}

	if clientID == "" || clientSecret == "" {
		log.Fatal("VOUCH_CLIENT_ID and VOUCH_CLIENT_SECRET are required")
	}

	ctx := context.Background()
	var err error
	oidcProvider, err = oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}

	verifier = oidcProvider.Verifier(&oidc.Config{ClientID: clientID})

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	log.Println("Server running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	var user *sessionData
	if err == nil {
		user = sessions[cookie.Value]
	}

	w.Header().Set("Content-Type", "text/html")
	if user != nil {
		hw := ""
		if user.HardwareVerified {
			hw = "<p><strong>Hardware Verified</strong></p>"
		}
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Vouch + Go</title></head><body>
<h1>Vouch OIDC + Go + go-oidc</h1>
<p>Signed in as %s</p>%s
<a href="/logout">Sign out</a>
</body></html>`, user.Email, hw)
	} else {
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Vouch + Go</title></head><body>
<h1>Vouch OIDC + Go + go-oidc</h1>
<a href="/login">Sign in with Vouch</a>
</body></html>`)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	states[state] = true
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !states[state] {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(states, state)

	code := r.URL.Query().Get("code")
	token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Token verification failed", http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email            string `json:"email"`
		HardwareVerified bool   `json:"hardware_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	sessionID := generateState()
	sessions[sessionID] = &sessionData{
		Email:            claims.Email,
		HardwareVerified: claims.HardwareVerified,
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
