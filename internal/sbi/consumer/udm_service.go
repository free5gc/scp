package consumer

import (
	"context"
	"sync"

	"github.com/free5gc/openapi/models"
	udmSDM "github.com/free5gc/openapi/udm/SDM"
	udmUEAU "github.com/free5gc/openapi/udm/UEAU"
)

type nudmService struct {
	consumer    *Consumer
	ueauMu      sync.RWMutex
	sdmMu       sync.RWMutex
	ueauClients map[string]*udmUEAU.APIClient
	sdmClients  map[string]*udmSDM.APIClient
}

func (s *nudmService) getUdmUeauClient(uri string) *udmUEAU.APIClient {
	if uri == "" {
		return nil
	}
	s.ueauMu.RLock()
	client := s.ueauClients[uri]
	s.ueauMu.RUnlock()
	if client != nil {
		return client
	}
	cfg := udmUEAU.NewConfiguration()
	cfg.SetBasePath(uri)
	client = udmUEAU.NewAPIClient(cfg)
	s.ueauMu.Lock()
	if existing := s.ueauClients[uri]; existing != nil {
		client = existing
	} else {
		s.ueauClients[uri] = client
	}
	s.ueauMu.Unlock()
	return client
}

func (s *nudmService) getUdmSDMClient(uri string) *udmSDM.APIClient {
	if uri == "" {
		return nil
	}
	s.sdmMu.RLock()
	client := s.sdmClients[uri]
	s.sdmMu.RUnlock()
	if client != nil {
		return client
	}
	cfg := udmSDM.NewConfiguration()
	cfg.SetBasePath(uri)
	client = udmSDM.NewAPIClient(cfg)
	s.sdmMu.Lock()
	if existing := s.sdmClients[uri]; existing != nil {
		client = existing
	} else {
		s.sdmClients[uri] = client
	}
	s.sdmMu.Unlock()
	return client
}

func (s *nudmService) SendGenerateAuthDataRequest(
	parent context.Context,
	uri, supiOrSuci string,
	authInfoReq *models.Udm_UEAU_AuthenticationInfoRequest,
) (*models.Udm_UEAU_AuthenticationInfoResult, error) {
	client := s.getUdmUeauClient(uri)
	if client == nil {
		return nil, nilResponse("UDM generate authentication data")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NUDM_UEAU, models.Nrf_NFMgmt_NFType_UDM)
	if err != nil {
		return nil, err
	}
	rsp, err := client.GenerateAuthDataApi.GenerateAuthData(ctx, &udmUEAU.GenerateAuthDataRequest{
		SupiOrSuci: &supiOrSuci, RequestBody: authInfoReq,
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil || rsp.Udm_UEAU_AuthenticationInfoResult == nil {
		return nil, nilResponse("UDM generate authentication data")
	}
	return rsp.Udm_UEAU_AuthenticationInfoResult, nil
}

func (s *nudmService) SendGetNSSAIRequest(
	parent context.Context,
	uri string,
	request *udmSDM.GetNSSAIRequest,
) (*udmSDM.GetNSSAIResponse, error) {
	client := s.getUdmSDMClient(uri)
	if client == nil {
		return nil, nilResponse("UDM NSSAI")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM)
	if err != nil {
		return nil, err
	}
	rsp, err := client.SliceSelectionSubscriptionDataRetrievalApi.GetNSSAI(ctx, request)
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil {
		return nil, nilResponse("UDM NSSAI")
	}
	return rsp, nil
}
