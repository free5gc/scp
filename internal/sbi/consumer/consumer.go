package consumer

import (
	Nausf_UEAuthentication "github.com/free5gc/openapi/ausf/UEAuthentication"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	Nudm_UEAuthentication "github.com/free5gc/openapi/udm/UEAuthentication"
	Nudr_DataRepository "github.com/free5gc/openapi/udr/DataRepository"
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
