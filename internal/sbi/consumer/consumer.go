package consumer

import (
	ausfAuth "github.com/free5gc/openapi/ausf/UEAuthentication"
	"github.com/free5gc/openapi/nrf/NFDiscovery"
	"github.com/free5gc/openapi/nrf/NFManagement"
	udmAuth "github.com/free5gc/openapi/udm/UEAuthentication"
	"github.com/free5gc/openapi/udr/DataRepository"
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
		nfDiscClients:   make(map[string]*NFDiscovery.APIClient),
		nfMngmntClients: make(map[string]*NFManagement.APIClient),
	}

	c.nudrService = &nudrService{
		consumer: c,
		clients:  make(map[string]*DataRepository.APIClient),
	}

	c.nausfService = &nausfService{
		consumer:                c,
		UEAuthenticationClients: make(map[string]*ausfAuth.APIClient),
	}

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*udmAuth.APIClient),
	}
	return c, nil
}
