package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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
var pkceVerifiers = map[string]string{}

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
	pkceVerifier := oauth2.GenerateVerifier()
	pkceVerifiers[state] = pkceVerifier
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(pkceVerifier)), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !states[state] {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(states, state)

	pkceVerifier := pkceVerifiers[state]
	delete(pkceVerifiers, state)

	code := r.URL.Query().Get("code")
	token, err := oauth2Config.Exchange(r.Context(), code, oauth2.VerifierOption(pkceVerifier))
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
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	atClaims, err := decodeAccessToken(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to decode access token", http.StatusInternalServerError)
		return
	}
	hwVerified, _ := atClaims["hardware_verified"].(bool)

	sessionID := generateState()
	sessions[sessionID] = &sessionData{
		Email:            claims.Email,
		HardwareVerified: hwVerified,
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

// Hardware claims (hardware_verified, hardware_aaguid) are in the
// access token JWT (RFC 9068), not the OIDC id_token.
func decodeAccessToken(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	return claims, err
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
