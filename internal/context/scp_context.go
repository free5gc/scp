package context

import (
	"context"
	"sync"

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

	nfInstID       string // NF Instance ID
	OAuth2Required bool
	mu             sync.RWMutex

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

var (
	NFtoUriMap map[string]string
	scpContext ScpContext
)

func NewContext(scp scp) (*ScpContext, error) {
	c := &ScpContext{
		scp:      scp,
		nfInstID: uuid.New().String(),
	}
	NFtoUriMap = make(map[string]string)
	scpContext.AmfUri = scp.Config().Configuration.AmfUri
	if scpContext.AmfUri != "" {
		NFtoUriMap["AMF"] = scpContext.AmfUri
	}
	scpContext.AusfUri = scp.Config().Configuration.AusfUri
	if scpContext.AusfUri != "" {
		NFtoUriMap["AUSF"] = scpContext.AusfUri
	}
	scpContext.ChfUri = scp.Config().Configuration.ChfUri
	if scpContext.ChfUri != "" {
		NFtoUriMap["CHF"] = scpContext.ChfUri
	}
	scpContext.NefUri = scp.Config().Configuration.NefUri
	if scpContext.NefUri != "" {
		NFtoUriMap["NEF"] = scpContext.NefUri
	}
	scpContext.NssfUri = scp.Config().Configuration.NssfUri
	if scpContext.NssfUri != "" {
		NFtoUriMap["NSSF"] = scpContext.NssfUri
	}
	scpContext.PcfUri = scp.Config().Configuration.PcfUri
	if scpContext.PcfUri != "" {
		NFtoUriMap["PCF"] = scpContext.PcfUri
	}
	scpContext.SmfUri = scp.Config().Configuration.SmfUri
	if scpContext.SmfUri != "" {
		NFtoUriMap["SMF"] = scpContext.SmfUri
	}
	scpContext.UdmUri = scp.Config().Configuration.UdmUri
	if scpContext.UdmUri != "" {
		NFtoUriMap["UDM"] = scpContext.UdmUri
	}
	scpContext.UdrUri = scp.Config().Configuration.UdrUri
	if scpContext.UdrUri != "" {
		NFtoUriMap["UDR"] = scpContext.UdrUri
	}
	scpContext.UpfUri = scp.Config().Configuration.UpfUri
	if scpContext.UpfUri != "" {
		NFtoUriMap["UPF"] = scpContext.UpfUri
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
	defer c.mu.Unlock()
	c.nfInstID = id
	logger.CtxLog.Infof("Set nfInstID: [%s]", c.nfInstID)
}

func (c *ScpContext) GetTokenCtx(serviceName models.ServiceName, targetNF models.NfType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(models.NfType_SCP, targetNF,
		c.nfInstID, c.Config().NrfUri(), string(serviceName))
}

func GetSelf() *ScpContext {
	return &scpContext
}
