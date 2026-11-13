package context

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/google/uuid"
)

type scp interface {
	Config() *factory.Config
}

type NFContext interface{}

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
) (context.Context, *models.ProblemDetails, error) {
	if parent == nil {
		parent = context.Background()
	}
	if !c.OAuth2Required() {
		return parent, nil, nil
	}
	return c.getTokenCtx(parent, c.tokenRequest(serviceName, targetNF))
}

func (c *ScpContext) GetTokenCtxForNFInstance(
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
	targetID, err := uuid.Parse(strings.TrimSpace(targetNFInstanceID))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target NF instance ID: %w", err)
	}
	if targetID.Version() != 4 {
		return nil, nil, fmt.Errorf("invalid target NF instance ID: UUID must be version 4")
	}
	return c.getTokenCtx(parent, c.tokenRequestForNFInstance(serviceName, targetNF, targetNFInstanceID))
}

func (c *ScpContext) GetTokenCtxForNRF(
	parent context.Context,
	serviceName models.Nrf_NFMgmt_ServiceName,
) (context.Context, *models.ProblemDetails, error) {
	c.mu.RLock()
	nrfNfInstanceID := c.nrfNfInstanceID
	c.mu.RUnlock()
	return c.GetTokenCtxForNFInstance(parent, serviceName, models.Nrf_NFMgmt_NFType_NRF, nrfNfInstanceID)
}

func (c *ScpContext) tokenRequest(
	serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType,
) oauth.TokenRequest {
	// TS 29.510 §6.3.5.2.2: AccessTokenReq identifies the consumer, target NF and requested service scope.
	return oauth.TokenRequest{
		ConsumerNFType:       models.Nrf_NFMgmt_NFType_SCP,
		ConsumerNFInstanceID: c.NfInstID(),
		TargetNFType:         targetNF,
		NRFURI:               c.Config().NrfUri(),
		Scope:                string(serviceName),
	}
}

func (c *ScpContext) tokenRequestForNFInstance(
	serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType,
	targetNFInstanceID string,
) oauth.TokenRequest {
	// TS 29.510 §6.3.5.2.2: targetNfInstanceId selects a specific NF service producer.
	request := c.tokenRequest(serviceName, targetNF)
	request.TargetNFInstanceID = targetNFInstanceID
	return request
}

// Preserve the caller's context when attaching the shared OpenAPI token source.
func (c *ScpContext) getTokenCtx(parent context.Context, request oauth.TokenRequest) (
	context.Context, *models.ProblemDetails, error,
) {
	tokenCtx, pd, err := oauth.GetTokenCtx(request)
	if err != nil {
		return nil, pd, err
	}
	return context.WithValue(parent, openapi.ContextOAuth2, tokenCtx.Value(openapi.ContextOAuth2)), nil, nil
}
