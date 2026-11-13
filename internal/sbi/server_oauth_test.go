package sbi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/sbi/processor"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type oauthTestApp struct {
	cfg *factory.Config
	ctx *scp_context.ScpContext
}

func (a *oauthTestApp) Config() *factory.Config          { return a.cfg }
func (a *oauthTestApp) Context() *scp_context.ScpContext { return a.ctx }
func (a *oauthTestApp) Processor() *processor.Processor  { return nil }

type proxyFixture struct {
	server            *Server
	key               *rsa.PrivateKey
	consumerKey       *rsa.PrivateKey
	issuer            string
	consumerID        string
	producerID        string
	nrfCalls          atomic.Int32
	producerCalls     atomic.Int32
	deny              bool
	wrongSubject      bool
	lastAuthorization string
	lastCCA           string
	lastConsumer      string
	lastBody          string
	producerStatus    int
}

func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	f := &proxyFixture{issuer: uuid.NewString(), consumerID: uuid.NewString(), producerID: uuid.NewString()}
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.consumerKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse("urn:uuid:" + f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), URIs: []*url.URL{identity},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &f.key.PublicKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	producer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.producerCalls.Add(1)
		f.lastAuthorization, f.lastCCA = r.Header.Get("Authorization"), r.Header.Get(ccaHeader)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		f.lastBody = string(body)
		status := f.producerStatus
		if status == 0 {
			status = http.StatusNoContent
		}
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer`)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(producer.Close)
	nrf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.nrfCalls.Add(1)
		if r.URL.Path != "/oauth2/token" || r.Method != http.MethodPost {
			t.Errorf("unexpected NRF request %s", r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		f.lastConsumer = r.Form.Get("nfInstanceId")
		claims := &jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(r.Header.Get(ccaHeader), claims,
			func(*jwt.Token) (interface{}, error) { return &f.consumerKey.PublicKey, nil },
			jwt.WithValidMethods([]string{"RS512"}), jwt.WithExpirationRequired(), jwt.WithAudience("NRF"))
		if f.deny || err != nil || claims.Subject != f.lastConsumer || !slices.Contains(claims.Audience, "AUSF") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := io.WriteString(w, `{"error":"invalid_client"}`); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Form.Get("nfType") != "AMF" || r.Form.Get("targetNfType") != "AUSF" ||
			r.Form.Get("scope") != "nausf-auth" || r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("incorrect delegated token request: %v", r.Form)
		}
		subject := f.lastConsumer
		if f.wrongSubject {
			subject = f.server.Context().NfInstID()
		}
		audience := "AUSF"
		if target := r.Form.Get("targetNfInstanceId"); target != "" {
			if target != f.producerID {
				t.Errorf("wrong target instance: %s", target)
			}
			audience = target
		}
		claimsMap := f.claims()
		claimsMap["sub"], claimsMap["aud"] = subject, audience
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": f.sign(t, claimsMap, f.key),
			"token_type": "Bearer", "expires_in": 300}); err != nil {
			t.Error(err)
		}
	}))
	nrf.Config.Protocols = new(http.Protocols)
	nrf.Config.Protocols.SetHTTP1(true)
	nrf.Config.Protocols.SetUnencryptedHTTP2(true)
	nrf.Start()
	t.Cleanup(nrf.Close)
	app := &oauthTestApp{cfg: &factory.Config{Configuration: &factory.Configuration{
		Sbi:    &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.113", BindingIPv4: "127.0.0.113", Port: 8000},
		NrfUri: nrf.URL, NrfCertPem: certPath, DelegatedOAuth: true,
		AusfUri: producer.URL, UdmUri: producer.URL, UdrUri: producer.URL,
		ServiceList: []factory.Service{{ServiceName: factory.ServiceNausfAuth},
			{ServiceName: factory.ServiceNudmUeau}, {ServiceName: factory.ServiceNudmSubManage},
			{ServiceName: factory.ServiceNudrDR}},
	}}}
	app.ctx, err = scp_context.NewContext(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ctx.SetOAuth2Required(true); err != nil {
		t.Fatal(err)
	}
	f.server, err = NewServer(app, "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *proxyFixture) claims() jwt.MapClaims {
	return jwt.MapClaims{"iss": f.issuer, "sub": f.consumerID, "aud": "AUSF",
		"exp": time.Now().Add(time.Minute).Unix(), "scope": "nausf-auth"}
}

func (f *proxyFixture) sign(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *proxyFixture) assertion(t *testing.T, consumerID string) string {
	t.Helper()
	// TS 33.501 §13.4.1.3.2: the original consumer CCA addresses NRF and the producer NF type.
	return f.sign(t, jwt.MapClaims{"sub": consumerID, "aud": []string{"NRF", "AUSF"},
		"exp": time.Now().Add(time.Minute).Unix()}, f.consumerKey)
}

func (f *proxyFixture) request(t *testing.T, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/nausf-auth/v1/ue-authentications",
		strings.NewReader(`{"supiOrSuci":"test"}`))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.server.router.ServeHTTP(w, r)
	return w
}

func TestProxyJWTValidation(t *testing.T) {
	f := newProxyFixture(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		change   func(jwt.MapClaims)
		wrongKey bool
		status   int
	}{
		{name: "valid producer type", status: 204},
		{name: "wrong issuer", change: func(c jwt.MapClaims) { c["iss"] = uuid.NewString() }, status: 401},
		{name: "wrong audience", change: func(c jwt.MapClaims) { c["aud"] = "SMF" }, status: 401},
		{name: "SCP is not producer audience",
			change: func(c jwt.MapClaims) { c["aud"] = f.server.Context().NfInstID() }, status: 401},
		{name: "expired", change: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, status: 401},
		{name: "missing expiration", change: func(c jwt.MapClaims) { delete(c, "exp") }, status: 401},
		{name: "wrong scope", change: func(c jwt.MapClaims) { c["scope"] = "nudm-ueau" }, status: 403},
		{name: "wrong signature", wrongKey: true, status: 401},
		{name: "missing subject", change: func(c jwt.MapClaims) { delete(c, "sub") }, status: 401},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			claims := f.claims()
			if tt.change != nil {
				tt.change(claims)
			}
			key := f.key
			if tt.wrongKey {
				key = wrongKey
			}
			auth := "Bearer " + f.sign(t, claims, key)
			before := f.producerCalls.Load()
			w := f.request(t, map[string]string{"Authorization": auth})
			if w.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.status, w.Body)
			}
			if tt.status == 204 {
				if f.lastAuthorization != auth {
					t.Fatal("consumer token was replaced")
				}
			} else {
				if f.producerCalls.Load() != before {
					t.Fatal("invalid token reached producer")
				}
				if w.Header().Get("WWW-Authenticate") == "" {
					t.Fatal("missing OAuth challenge")
				}
			}
		})
	}
	if f.nrfCalls.Load() != 0 {
		t.Fatal("consumer-supplied tokens must not trigger token acquisition")
	}
}

func TestDelegatedTokenPreservesConsumer(t *testing.T) {
	f := newProxyFixture(t)
	for _, consumerID := range []string{f.consumerID, uuid.NewString()} {
		cca := f.assertion(t, consumerID)
		w := f.request(t, map[string]string{consumerIDHeader: consumerID, consumerTypeHeader: "AMF",
			accessScopeHeader: "nausf-auth", ccaHeader: cca})
		if w.Code != 204 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
		if f.lastConsumer != consumerID || f.lastConsumer == f.server.Context().NfInstID() {
			t.Fatal("SCP replaced consumer ID")
		}
		sub, err := scp_context.TokenSubject(f.lastAuthorization)
		if err != nil || sub != consumerID {
			t.Fatalf("subject=%s err=%v", sub, err)
		}
		if f.lastCCA != cca {
			t.Fatal("consumer CCA was not preserved")
		}
		if f.lastBody != `{"supiOrSuci":"test"}` {
			t.Fatal("request body changed")
		}
	}
	if f.nrfCalls.Load() != 2 {
		t.Fatal("delegated requests crossed consumer authentication boundaries")
	}
}

func TestProxyDelegationFailures(t *testing.T) {
	f := newProxyFixture(t)
	cca := f.assertion(t, f.consumerID)
	valid := func() map[string]string {
		return map[string]string{consumerIDHeader: f.consumerID, consumerTypeHeader: "AMF",
			accessScopeHeader: "nausf-auth", ccaHeader: cca}
	}
	for _, name := range []string{consumerIDHeader, consumerTypeHeader, accessScopeHeader} {
		headers := valid()
		delete(headers, name)
		w := f.request(t, headers)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "MISSING_ACCESS_TOKEN_INFO") {
			t.Fatalf("missing %s: %d %s", name, w.Code, w.Body)
		}
	}
	headers := valid()
	delete(headers, ccaHeader)
	if w := f.request(t, headers); w.Code != 403 {
		t.Fatalf("unauthenticated identity accepted: %d", w.Code)
	}
	headers = valid()
	headers[consumerIDHeader] = uuid.NewString()
	if w := f.request(t, headers); w.Code != 403 {
		t.Fatalf("CCA subject mismatch accepted: %d", w.Code)
	}
	f.wrongSubject = true
	if w := f.request(t, valid()); w.Code != 502 {
		t.Fatalf("NRF token with SCP subject accepted: %d", w.Code)
	}
	if f.producerCalls.Load() != 0 {
		t.Fatal("failed delegation reached producer")
	}
}

func TestProxyNotifyDoesNotAcquireToken(t *testing.T) {
	f := newProxyFixture(t)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/nudm-callback/v1/test/sdm-subscriptions",
		strings.NewReader(`{"notify":true}`))
	r.Header.Set(callbackHeader, "Nudr_DataRepository_DataChangeNotify")
	w := httptest.NewRecorder()
	f.server.router.ServeHTTP(w, r)
	if w.Code != 204 || f.nrfCalls.Load() != 0 || f.producerCalls.Load() != 1 || f.lastAuthorization != "" {
		t.Fatalf("Notify unexpectedly used OAuth: status=%d nrf=%d authPresent=%t",
			w.Code, f.nrfCalls.Load(), f.lastAuthorization != "")
	}
}

func TestProxyInstanceAudience(t *testing.T) {
	f := newProxyFixture(t)
	f.server.Config().Configuration.ServiceList[0].ProducerNFInstanceID = f.producerID
	claims := f.claims()
	claims["aud"] = f.producerID
	w := f.request(t, map[string]string{"Authorization": "Bearer " + f.sign(t, claims, f.key)})
	if w.Code != 204 {
		t.Fatalf("configured instance audience rejected: %d %s", w.Code, w.Body)
	}
	claims["aud"] = uuid.NewString()
	if w = f.request(t, map[string]string{"Authorization": "Bearer " + f.sign(t, claims, f.key)}); w.Code != 401 {
		t.Fatalf("wrong instance audience accepted: %d", w.Code)
	}
	cca := f.assertion(t, f.consumerID)
	w = f.request(t, map[string]string{consumerIDHeader: f.consumerID, consumerTypeHeader: "AMF",
		accessScopeHeader: "nausf-auth", ccaHeader: cca})
	if w.Code != 204 {
		t.Fatalf("instance-bound delegated token failed: %d %s", w.Code, w.Body)
	}
}

func TestProxyJWTForConfiguredServices(t *testing.T) {
	f := newProxyFixture(t)
	for _, tt := range []struct{ service, method, path, target string }{
		{"nausf-auth", http.MethodPost, "/nausf-auth/v1/ue-authentications", "AUSF"},
		{"nudm-ueau", http.MethodPost, "/nudm-ueau/v1/test/security-information/generate-auth-data", "UDM"},
		{"nudm-sdm", http.MethodGet, "/nudm-sdm/v2/test/nssai", "UDM"},
		{"nudr-dr", http.MethodGet,
			"/nudr-dr/v2/subscription-data/test/authentication-data/authentication-subscription", "UDR"},
	} {
		t.Run(tt.service, func(t *testing.T) {
			claims := f.claims()
			claims["scope"], claims["aud"] = tt.service, tt.target
			r := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			r.Header.Set("Authorization", "Bearer "+f.sign(t, claims, f.key))
			w := httptest.NewRecorder()
			f.server.router.ServeHTTP(w, r)
			if w.Code != 204 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			before := f.producerCalls.Load()
			claims["scope"] = "unrelated-service"
			r = httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			r.Header.Set("Authorization", "Bearer "+f.sign(t, claims, f.key))
			w = httptest.NewRecorder()
			f.server.router.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || f.producerCalls.Load() != before {
				t.Fatalf("route group did not reject the wrong scope: status=%d", w.Code)
			}
		})
	}
}

func TestProxyNotifyRelaysProducerChallenge(t *testing.T) {
	f := newProxyFixture(t)
	f.producerStatus = http.StatusUnauthorized
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/nudm-callback/v1/test/sdm-subscriptions", nil)
	r.Header.Set(callbackHeader, "Nudr_DataRepository_DataChangeNotify")
	w := httptest.NewRecorder()
	f.server.router.ServeHTTP(w, r)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" || f.nrfCalls.Load() != 0 {
		t.Fatalf("Notify challenge must be relayed without token acquisition: %d %s", w.Code, w.Body)
	}
}

func TestProxyDelegationDisabledByDefault(t *testing.T) {
	f := newProxyFixture(t)
	f.server.Config().Configuration.DelegatedOAuth = false
	w := f.request(t, map[string]string{consumerIDHeader: f.consumerID, consumerTypeHeader: "AMF",
		accessScopeHeader: "nausf-auth", ccaHeader: "unverified-assertion"})
	if w.Code != 403 || f.nrfCalls.Load() != 0 || f.producerCalls.Load() != 0 {
		t.Fatalf("disabled delegation must fail without using legacy NRF authentication: %d", w.Code)
	}
}
