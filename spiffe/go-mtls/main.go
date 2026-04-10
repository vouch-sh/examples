package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	x509Source *workloadapi.X509Source
	verifier   *oidc.IDTokenVerifier
)

func main() {
	vouchIssuer := os.Getenv("VOUCH_ISSUER")
	if vouchIssuer == "" {
		vouchIssuer = "https://us.vouch.sh"
	}
	clientID := os.Getenv("VOUCH_CLIENT_ID")
	if clientID == "" {
		log.Fatal("VOUCH_CLIENT_ID is required")
	}

	ctx := context.Background()

	// Connect to SPIFFE Workload API for X.509-SVIDs
	var err error
	x509Source, err = workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("Failed to create X509Source: %v", err)
	}
	defer x509Source.Close()

	svid, err := x509Source.GetX509SVID()
	if err != nil {
		log.Fatalf("Failed to get X509-SVID: %v", err)
	}
	log.Printf("Server SPIFFE ID: %s", svid.ID)

	// Set up Vouch OIDC provider for JWT verification
	provider, err := oidc.NewProvider(ctx, vouchIssuer)
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Create mTLS config: SPIFFE X.509-SVIDs for transport, accept any SPIFFE peer
	tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	listener, err := tls.Listen("tcp", ":3000", tlsCfg)
	if err != nil {
		log.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/whoami", handleWhoami)

	log.Println("Server running on https://localhost:3000 (SPIFFE mTLS)")
	log.Fatal((&http.Server{Handler: mux}).Serve(listener))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	svid, _ := x509Source.GetX509SVID()
	peerID := peerSPIFFEID(r)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>SPIFFE mTLS + Vouch</title></head><body>
<h1>SPIFFE mTLS + Vouch OIDC</h1>
<p><strong>Server SPIFFE ID:</strong> %s</p>
<p><strong>Peer SPIFFE ID:</strong> %s</p>
<p>Send a request to <code>/whoami</code> with an <code>Authorization: Bearer &lt;vouch-jwt&gt;</code> header to see both identities.</p>
</body></html>`, svid.ID, peerID)
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	peerID := peerSPIFFEID(r)

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, `{"error":"Authorization: Bearer <vouch-jwt> header required"}`, http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	idToken, err := verifier.Verify(r.Context(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"token verification failed: %s"}`, err), http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email            string `json:"email"`
		Sub              string `json:"sub"`
		HardwareVerified bool   `json:"hardware_verified"`
		HardwareAAGUID   string `json:"hardware_aaguid,omitempty"`
	}
	idToken.Claims(&claims)

	svid, _ := x509Source.GetX509SVID()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"workload_identity": map[string]any{
			"server_spiffe_id": svid.ID.String(),
			"peer_spiffe_id":   peerID,
		},
		"user_identity": map[string]any{
			"email":             claims.Email,
			"sub":               claims.Sub,
			"hardware_verified": claims.HardwareVerified,
			"hardware_aaguid":   claims.HardwareAAGUID,
		},
	})
}

func peerSPIFFEID(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			id, err := spiffeid.FromURI(uri)
			if err == nil {
				return id.String()
			}
		}
	}
	return "unknown"
}
