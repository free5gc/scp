package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	Nudm_UEAU "github.com/free5gc/openapi/udm/UEAuthentication"
	"github.com/free5gc/openapi/models"
)

type nudmService struct {
	consumer *Consumer

	ueauMu sync.RWMutex

	ueauClients map[string]*Nudm_UEAU.APIClient
}

func (s *nudmService) getUdmUeauClient(uri string) *Nudm_UEAU.APIClient {
	if uri == "" {
		return nil
	}
	s.ueauMu.RLock()
	client, ok := s.ueauClients[uri]
	if ok {
		s.ueauMu.RUnlock()
		return client
	}

	configuration := Nudm_UEAU.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nudm_UEAU.NewAPIClient(configuration)

	s.ueauMu.RUnlock()
	s.ueauMu.Lock()
	defer s.ueauMu.Unlock()
	s.ueauClients[uri] = client
	return client
}

func (s *nudmService) SendGenerateAuthDataRequest(uri string,
	supiOrSuci string, authInfoReq *models.UdmUeauAuthenticationInfoRequest,
) (*models.UdmUeauAuthenticationInfoResult, *models.ProblemDetails, error) {
	client := s.getUdmUeauClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDM_UEAU, models.NrfNfManagementNfType_UDM)
	if err != nil {
		return nil, nil, err
	}

	req := &Nudm_UEAU.GenerateAuthDataRequest{
		SupiOrSuci:                       &supiOrSuci,
		UdmUeauAuthenticationInfoRequest: authInfoReq,
	}
	res, err := client.GenerateAuthDataApi.GenerateAuthData(ctx, req)
	if err != nil {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, err
	}
	return &res.UdmUeauAuthenticationInfoResult, nil, nil
}
