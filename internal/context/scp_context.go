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
}

func NewContext(scp scp) (*ScpContext, error) {
	c := &ScpContext{
		scp:      scp,
		nfInstID: uuid.New().String(),
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
