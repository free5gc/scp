package context

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/AccTok"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type scp interface {
	Config() *factory.Config
}

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error
}

var _ NFContext = &ScpContext{}

type ScpContext struct {
	scp

	mu              sync.RWMutex
	nfInstID        string
	nrfNfInstanceID string
	oauth2Required  bool
	nfToURI         map[string]string

	AmfUri  string
	AusfUri string
	ChfUri  string
	NefUri  string
	NssfUri string
	PcfUri  string
	SmfUri  string
	UdmUri  string
	UdrUri  string
	UpfUri  string
}

func NewContext(scp scp) (*ScpContext, error) {
	cfg := scp.Config().Configuration
	c := &ScpContext{
		scp:      scp,
		nfInstID: uuid.New().String(),
		nfToURI:  make(map[string]string),
		AmfUri:   cfg.AmfUri,
		AusfUri:  cfg.AusfUri,
		ChfUri:   cfg.ChfUri,
		NefUri:   cfg.NefUri,
		NssfUri:  cfg.NssfUri,
		PcfUri:   cfg.PcfUri,
		SmfUri:   cfg.SmfUri,
		UdmUri:   cfg.UdmUri,
		UdrUri:   cfg.UdrUri,
		UpfUri:   cfg.UpfUri,
	}

	for nf, uri := range map[string]string{
		"AMF": c.AmfUri, "AUSF": c.AusfUri, "CHF": c.ChfUri,
		"NEF": c.NefUri, "NSSF": c.NssfUri, "PCF": c.PcfUri,
		"SMF": c.SmfUri, "UDM": c.UdmUri, "UDR": c.UdrUri,
		"UPF": c.UpfUri,
	} {
		if uri != "" {
			c.nfToURI[nf] = uri
		}
	}

	logger.CtxLog.Infof("New nfInstID: [%s]", c.nfInstID)
	return c, nil
}

func (c *ScpContext) NfInstID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nfInstID
}

func (c *ScpContext) SetNfInstID(id string) {
	c.mu.Lock()
	c.nfInstID = id
	c.mu.Unlock()
	logger.CtxLog.Infof("Set nfInstID: [%s]", id)
}

func (c *ScpContext) OAuth2Required() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.oauth2Required
}

func (c *ScpContext) SetOAuth2Required(required bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !required {
		c.oauth2Required = false
		c.nrfNfInstanceID = ""
		return nil
	}
	if strings.TrimSpace(c.Config().NrfCertPem()) == "" {
		return fmt.Errorf("OAuth2 enabled but NRF certificate path is empty")
	}
	if strings.TrimSpace(c.Config().NrfUri()) == "" {
		return fmt.Errorf("OAuth2 enabled but NRF URI is empty")
	}
	nrfID, err := oauth.NFInstanceIDFromCertificate(c.Config().NrfCertPem())
	if err != nil {
		return fmt.Errorf("derive trusted NRF instance ID from certificate: %w", err)
	}
	c.nrfNfInstanceID = nrfID
	c.oauth2Required = required
	return nil
}

func (c *ScpContext) URIForNF(nf string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nfToURI[strings.ToUpper(nf)]
}

// TS 33.501 §13.4.1.3.2: delegated token acquisition must retain the original NF consumer's identity.
// This helper currently requests tokens as the SCP itself; it does not implement delegated acquisition.
func (c *ScpContext) GetTokenCtx(
	parent context.Context,
	serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType,
	targetNFInstanceID string,
) (context.Context, *models.ProblemDetails, error) {
	if parent == nil {
		parent = context.Background()
	}
	if !c.OAuth2Required() {
		return parent, nil, nil
	}
	if targetNFInstanceID != "" {
		targetID, err := uuid.Parse(targetNFInstanceID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid target NF instance ID: %w", err)
		}
		if targetID.Version() != 4 {
			return nil, nil, fmt.Errorf("invalid target NF instance ID: UUID must be version 4")
		}
	}
	// TS 29.510 §6.3.5.2.2
	tokenCtx, pd, err := oauth.GetTokenCtx(oauth.TokenRequest{
		ConsumerNFType:       models.Nrf_NFMgmt_NFType_SCP,
		ConsumerNFInstanceID: c.NfInstID(),
		TargetNFType:         targetNF,
		NRFURI:               c.Config().NrfUri(),
		Scope:                string(serviceName),
		TargetNFInstanceID:   targetNFInstanceID,
	})
	if err != nil {
		return nil, pd, err
	}
	// Preserve the caller context when attaching the token source.
	return context.WithValue(parent, openapi.ContextOAuth2, tokenCtx.Value(openapi.ContextOAuth2)), nil, nil
}

func (c *ScpContext) GetTokenCtxForNRF(
	parent context.Context,
	serviceName models.Nrf_NFMgmt_ServiceName,
) (context.Context, *models.ProblemDetails, error) {
	c.mu.RLock()
	nrfNfInstanceID := c.nrfNfInstanceID
	c.mu.RUnlock()
	return c.GetTokenCtx(parent, serviceName, models.Nrf_NFMgmt_NFType_NRF, nrfNfInstanceID)
}

func (c *ScpContext) ProducerAudience(serviceName models.Nrf_NFMgmt_ServiceName) (oauth.AudiencePolicy, error) {
	producer, known := ProducerNFType(serviceName)
	if !known {
		return oauth.AudiencePolicy{}, fmt.Errorf("unsupported proxy service %s", serviceName)
	}
	for _, service := range c.Config().ServiceList() {
		if service.ServiceName == string(serviceName) {
			return oauth.AudiencePolicy{NFType: producer, NFInstanceID: service.ProducerNFInstanceID}, nil
		}
	}
	return oauth.AudiencePolicy{}, fmt.Errorf("proxy service %s is not configured", serviceName)
}

// TS 33.501 §13.4.1.3: the audience remains the producer; producer-side validation is still required.
func (c *ScpContext) AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error {
	if !c.OAuth2Required() {
		return nil
	}
	audience, err := c.ProducerAudience(serviceName)
	if err != nil {
		return err
	}
	c.mu.RLock()
	issuer := c.nrfNfInstanceID
	c.mu.RUnlock()
	return oauth.VerifyOAuth(token, string(serviceName), audience, issuer, c.Config().NrfCertPem())
}

func TokenSubject(authorization string) (string, error) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid Bearer header")
	}
	claims := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(parts[1], claims); err != nil {
		return "", err
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil || id.Version() != 4 {
		return "", errors.New("invalid consumer NF instance ID in token subject")
	}
	return claims.Subject, nil
}

type DelegatedTokenRequest struct {
	ConsumerNFInstanceID       string
	ConsumerNFType             models.Nrf_NFMgmt_NFType
	ServiceName                models.Nrf_NFMgmt_ServiceName
	Scope                      string
	ClientCredentialsAssertion string
}

// TS 29.500 §6.10.11.2.1: obtain an access token on behalf of the original consumer for delegated discovery.
// Disabled by default; enable only when SCP is officially enabled in the deployment.
func (c *ScpContext) GetDelegatedTokenCtx(parent context.Context, request DelegatedTokenRequest) (
	context.Context, *models.ProblemDetails, error,
) {
	if parent == nil {
		parent = context.Background()
	}
	if !c.Config().Configuration.DelegatedOAuth {
		return nil, &models.ProblemDetails{Status: 403, Cause: "ACCESS_TOKEN_DENIED"},
			errors.New("delegated OAuth requires an NRF with original consumer authentication support")
	}
	id, err := uuid.Parse(request.ConsumerNFInstanceID)
	if err != nil || id.Version() != 4 || request.ConsumerNFType == "" ||
		!slices.Contains(strings.Fields(request.Scope), string(request.ServiceName)) {
		return nil, nil, errors.New("invalid delegated consumer or scope")
	}
	audience, err := c.ProducerAudience(request.ServiceName)
	if err != nil {
		return nil, nil, err
	}

	// TS 33.501 §13.4.1.3.2: request the token for the original NF consumer, not for SCP.
	req := &AccTok.AccessTokenRequestRequest{}
	req.SetGrantType("client_credentials")
	req.SetNfInstanceId(request.ConsumerNFInstanceID)
	req.SetNfType(request.ConsumerNFType)
	req.SetTargetNfType(audience.NFType)
	req.SetScope(request.Scope)
	if audience.NFInstanceID != "" {
		req.SetTargetNfInstanceId(audience.NFInstanceID)
	}
	cfg := AccTok.NewConfiguration()
	cfg.SetBasePath(c.Config().NrfUri())
	if request.ClientCredentialsAssertion != "" {
		// TS 33.501 §13.4.1.3.2: preserve the consumer's CCA for NRF authentication.
		req.SetClientCredentialsAssertion(request.ClientCredentialsAssertion)
	}
	client := AccTok.NewAPIClient(cfg)
	rsp, err := client.AccessTokenRequestApi.AccessTokenRequest(parent, req)
	if err != nil {
		pd := &models.ProblemDetails{Status: 403, Cause: "ACCESS_TOKEN_DENIED"}
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorStatus >= 500 {
				pd.Status, pd.Cause = 502, "SYSTEM_FAILURE"
			}
			if body, ok := apiErr.Model().(AccTok.AccessTokenRequestError); ok {
				pd.AccessTokenError = body.Nrf_AccTok_AccessTokenErr
			}
		} else {
			pd.Status, pd.Cause = 504, "NRF_NOT_REACHABLE"
		}
		return nil, pd, fmt.Errorf("request delegated access token: %w", err)
	}
	if rsp == nil || rsp.Nrf_AccTok_AccessTokenRsp == nil {
		return nil, &models.ProblemDetails{Status: 502, Cause: "SYSTEM_FAILURE"}, errors.New("NRF token response is empty")
	}
	token := rsp.Nrf_AccTok_AccessTokenRsp
	if !strings.EqualFold(token.Token_type, "Bearer") {
		return nil, &models.ProblemDetails{Status: 502, Cause: "SYSTEM_FAILURE"}, errors.New("NRF token type is not Bearer")
	}
	authorization := "Bearer " + token.Access_token
	if err := c.AuthorizationCheck(authorization, request.ServiceName); err != nil {
		return nil, &models.ProblemDetails{Status: 502, Cause: "SYSTEM_FAILURE"}, fmt.Errorf("invalid NRF token: %w", err)
	}
	subject, err := TokenSubject(authorization)
	if err != nil || subject != request.ConsumerNFInstanceID {
		return nil, &models.ProblemDetails{Status: 502, Cause: "SYSTEM_FAILURE"}, errors.New("NRF token subject mismatch")
	}
	source := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.Access_token, TokenType: "Bearer"})
	return context.WithValue(parent, openapi.ContextOAuth2, source), nil, nil
}
