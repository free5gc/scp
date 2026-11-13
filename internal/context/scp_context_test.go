package context

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type oauthTestScp struct {
	cfg *factory.Config
}

func (s oauthTestScp) Config() *factory.Config { return s.cfg }

func writeNrfCertificate(t *testing.T, nrfID string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("urn:uuid:" + nrfID)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nrf.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newOAuthTestContext(t *testing.T, nrfURI string) *ScpContext {
	t.Helper()
	c, err := NewContext(oauthTestScp{cfg: &factory.Config{
		Configuration: &factory.Configuration{NrfUri: nrfURI},
	}})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	return c
}

func TestGetTokenCtxOAuthDisabled(t *testing.T) {
	c := newOAuthTestContext(t, "")
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()

	ctx, pd, err := c.GetTokenCtx(parent, models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil || pd != nil || ctx != parent {
		t.Fatalf("disabled OAuth must return the parent context: ctx=%v pd=%+v err=%v", ctx, pd, err)
	}
	if ctx.Value(openapi.ContextOAuth2) != nil {
		t.Fatal("disabled OAuth returned a token")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("disabled OAuth lost parent cancellation")
	}

	//nolint:staticcheck // Exercise GetTokenCtx's explicit nil-parent fallback.
	ctx, pd, err = c.GetTokenCtx(nil, models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil || pd != nil || ctx == nil || ctx.Err() != nil {
		t.Fatalf("nil parent must use a background context: pd=%+v err=%v", pd, err)
	}
}

func TestGetTokenCtxOAuthEnabled(t *testing.T) {
	tests := []struct {
		name      string
		service   models.Nrf_NFMgmt_ServiceName
		target    models.Nrf_NFMgmt_NFType
		nilParent bool
		nrfHelper bool
	}{
		{
			name: "NRF discovery", service: models.Nrf_NFMgmt_ServiceName_NNRF_DISC,
			target: models.Nrf_NFMgmt_NFType_NRF, nrfHelper: true,
		},
		{
			name: "NRF management helper", service: models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
			target: models.Nrf_NFMgmt_NFType_NRF, nrfHelper: true,
		},
		{
			name: "explicit type-level NRF request", service: models.Nrf_NFMgmt_ServiceName_NNRF_DISC,
			target: models.Nrf_NFMgmt_NFType_NRF,
		},
		{
			name: "AUSF authentication", service: models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH,
			target: models.Nrf_NFMgmt_NFType_AUSF,
		},
		{
			name: "UDR request with nil parent", service: models.Nrf_NFMgmt_ServiceName_NUDR_DR,
			target: models.Nrf_NFMgmt_NFType_UDR, nilParent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			var consumerID string
			nrfID := uuid.NewString()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/oauth2/token" {
					t.Errorf("unexpected token request: %s %s", r.Method, r.URL.Path)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse token request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				targetID := ""
				if tt.nrfHelper {
					targetID = nrfID
				}
				// TS 29.510 §6.3.5.2.2: NRF API calls select the trusted NRF instance.
				for key, want := range map[string]string{
					"grant_type": "client_credentials", "nfInstanceId": consumerID, "nfType": "SCP",
					"targetNfType": string(tt.target), "scope": string(tt.service), "targetNfInstanceId": targetID,
				} {
					if got := r.PostForm.Get(key); got != want {
						t.Errorf("%s = %q, want %q", key, got, want)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"access_token": "scp-fixture-token", "token_type": "Bearer", "expires_in": 3600,
				}); err != nil {
					t.Errorf("write token response: %v", err)
				}
			}))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetHTTP1(true)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Start()
			defer server.Close()

			c := newOAuthTestContext(t, server.URL)
			consumerID = c.NfInstID()
			c.Config().Configuration.NrfCertPem = writeNrfCertificate(t, nrfID)
			if err := c.SetOAuth2Required(true); err != nil {
				t.Fatal(err)
			}
			type contextKey struct{}
			parent, cancel := context.WithTimeout(context.WithValue(t.Context(), contextKey{}, "request"), time.Minute)
			defer cancel()
			requestCtx := parent
			if tt.nilParent {
				requestCtx = nil
			}
			var ctx context.Context
			var pd *models.ProblemDetails
			var err error
			if tt.nrfHelper {
				ctx, pd, err = c.GetTokenCtxForNRF(requestCtx, tt.service)
			} else {
				ctx, pd, err = c.GetTokenCtx(requestCtx, tt.service, tt.target)
			}
			if err != nil || pd != nil || ctx == nil {
				t.Fatalf("GetTokenCtx: pd=%+v err=%v", pd, err)
			}
			source, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
			if !ok {
				t.Fatal("returned context has no OAuth token source")
			}
			token, err := source.Token()
			if err != nil || token.AccessToken != "scp-fixture-token" || token.TokenType != "Bearer" {
				t.Fatalf("unexpected token: err=%v", err)
			}
			if !tt.nilParent {
				deadline, hasDeadline := ctx.Deadline()
				wantDeadline, _ := parent.Deadline()
				if ctx.Value(contextKey{}) != "request" || !hasDeadline || !deadline.Equal(wantDeadline) {
					t.Fatal("OAuth context lost parent values or deadline")
				}
				cancel()
				if ctx.Err() != context.Canceled {
					t.Fatal("OAuth context lost parent cancellation")
				}
			}

			if tt.nrfHelper {
				_, pd, err = c.GetTokenCtxForNRF(t.Context(), tt.service)
			} else {
				_, pd, err = c.GetTokenCtx(t.Context(), tt.service, tt.target)
			}
			if err != nil || pd != nil {
				t.Fatalf("cached GetTokenCtx: pd=%+v err=%v", pd, err)
			}
			if calls.Load() != 1 {
				t.Fatalf("token requests = %d, want 1 with caching", calls.Load())
			}
		})
	}
}

func TestGetTokenCtxForNFInstanceRejectsInvalidID(t *testing.T) {
	c := newOAuthTestContext(t, "http://nrf.example.com")
	c.Config().Configuration.NrfCertPem = writeNrfCertificate(t, uuid.NewString())
	if err := c.SetOAuth2Required(true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "not-a-uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"} {
		ctx, _, err := c.GetTokenCtxForNFInstance(t.Context(),
			models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF, id)
		if err == nil || ctx != nil {
			t.Fatalf("invalid target %q must fail without a token context", id)
		}
	}
	if err := c.SetOAuth2Required(false); err != nil {
		t.Fatal(err)
	}
	parent := t.Context()
	ctx, pd, err := c.GetTokenCtxForNRF(parent, models.Nrf_NFMgmt_ServiceName_NNRF_DISC)
	if err != nil || pd != nil || ctx != parent {
		t.Fatal("disabled OAuth must preserve the parent without validating the target")
	}
}

func TestGetTokenCtxTokenRequestFailure(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	c := newOAuthTestContext(t, server.URL)
	c.Config().Configuration.NrfCertPem = writeNrfCertificate(t, uuid.NewString())
	if err := c.SetOAuth2Required(true); err != nil {
		t.Fatal(err)
	}

	ctx, _, err := c.GetTokenCtx(t.Context(), models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err == nil || ctx != nil {
		t.Fatalf("NRF failure must return an error without a token context: ctx=%v err=%v", ctx, err)
	}
}

func TestSetOAuth2Required(t *testing.T) {
	for _, name := range []string{"missing certificate", "unreadable certificate", "invalid certificate"} {
		t.Run(name, func(t *testing.T) {
			c := newOAuthTestContext(t, "http://nrf.example.com")
			switch name {
			case "unreadable certificate":
				c.Config().Configuration.NrfCertPem = filepath.Join(t.TempDir(), "missing.pem")
			case "invalid certificate":
				path := filepath.Join(t.TempDir(), "invalid.pem")
				if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
					t.Fatal(err)
				}
				c.Config().Configuration.NrfCertPem = path
			}
			if err := c.SetOAuth2Required(true); err == nil {
				t.Fatal("invalid NRF certificate must prevent OAuth initialization")
			}
			if c.OAuth2Required() || c.nrfNfInstanceID != "" {
				t.Fatal("failed initialization published OAuth state")
			}
		})
	}
	t.Run("disable clears NRF identity", func(t *testing.T) {
		c := newOAuthTestContext(t, "http://nrf.example.com")
		id := uuid.NewString()
		c.Config().Configuration.NrfCertPem = writeNrfCertificate(t, id)
		if err := c.SetOAuth2Required(true); err != nil {
			t.Fatal(err)
		}
		if !c.OAuth2Required() || c.nrfNfInstanceID != id {
			t.Fatal("OAuth initialization did not publish the certificate identity")
		}
		if err := c.SetOAuth2Required(false); err != nil {
			t.Fatal(err)
		}
		if c.OAuth2Required() || c.nrfNfInstanceID != "" {
			t.Fatal("disabling OAuth did not clear the NRF identity")
		}
	})
}
