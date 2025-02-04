package consumer

import (
	"github.com/free5gc/openapi/Nausf_UEAuthentication"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/pkg/factory"
)

type scp interface {
	Context() *scp_context.ScpContext
	Config() *factory.Config
}

type Consumer struct {
	scp

	// consumer services
	*nnrfService
	*nausfService
	*nudmService
	*nudrService
}

func NewConsumer(scp scp) (*Consumer, error) {
	c := &Consumer{
		scp: scp,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfDiscClients:   make(map[string]*Nnrf_NFDiscovery.APIClient),
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
	}

	c.nudrService = &nudrService{
		consumer: c,
		clients:  make(map[string]*Nudr_DataRepository.APIClient),
	}

	c.nausfService = &nausfService{
		consumer:                c,
		UEAuthenticationClients: make(map[string]*Nausf_UEAuthentication.APIClient),
	}

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*Nudm_UEAuthentication.APIClient),
	}
	return c, nil
}
