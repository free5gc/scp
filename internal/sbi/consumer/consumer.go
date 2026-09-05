package consumer

import (
	ausfUEAU "github.com/free5gc/openapi/ausf/UEAU"
	nrfNFDisc "github.com/free5gc/openapi/nrf/NFDisc"
	nrfNFMgmt "github.com/free5gc/openapi/nrf/NFMgmt"
	udmSDM "github.com/free5gc/openapi/udm/SDM"
	udmUEAU "github.com/free5gc/openapi/udm/UEAU"
	udrDR "github.com/free5gc/openapi/udr/DR"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/pkg/factory"
)

type scp interface {
	Context() *scp_context.ScpContext
	Config() *factory.Config
}

type Consumer struct {
	scp

	*nnrfService
	*nausfService
	*nudmService
	*nudrService
}

func NewConsumer(scp scp) (*Consumer, error) {
	c := &Consumer{scp: scp}
	c.nnrfService = &nnrfService{
		consumer:        c,
		nfDiscClients:   make(map[string]*nrfNFDisc.APIClient),
		nfMngmntClients: make(map[string]*nrfNFMgmt.APIClient),
	}
	c.nudrService = &nudrService{consumer: c, clients: make(map[string]*udrDR.APIClient)}
	c.nausfService = &nausfService{consumer: c, clients: make(map[string]*ausfUEAU.APIClient)}
	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*udmUEAU.APIClient),
		sdmClients:  make(map[string]*udmSDM.APIClient),
	}
	return c, nil
}
