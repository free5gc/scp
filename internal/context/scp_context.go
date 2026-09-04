package context

import (
	"context"
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

	mu             sync.RWMutex
	nfInstID       string
	oauth2Required bool
	nfToURI        map[string]string

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

func (c *ScpContext) SetOAuth2Required(required bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.oauth2Required = required
}

func (c *ScpContext) URIForNF(nf string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nfToURI[strings.ToUpper(nf)]
}

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
	tokenCtx, pd, err := oauth.GetTokenCtx(models.Nrf_NFMgmt_NFType_SCP, targetNF,
		c.NfInstID(), c.Config().NrfUri(), string(serviceName))
	if err != nil {
		return nil, pd, err
	}
	return context.WithValue(parent, openapi.ContextOAuth2, tokenCtx.Value(openapi.ContextOAuth2)), nil, nil
}
