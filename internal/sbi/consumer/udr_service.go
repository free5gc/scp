package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nudr_DataRepository "github.com/free5gc/openapi/udr/DataRepository"
	scp_context "github.com/free5gc/scp/internal/context"
)

type nudrService struct {
	consumer *Consumer

	mu      sync.RWMutex
	clients map[string]*Nudr_DataRepository.APIClient
}

func (s *nudrService) getClient(uri string) *Nudr_DataRepository.APIClient {
	s.mu.RLock()
	if client, ok := s.clients[uri]; ok {
		defer s.mu.RUnlock()
		return client
	} else {
		configuration := Nudr_DataRepository.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := Nudr_DataRepository.NewAPIClient(configuration)

		s.mu.RUnlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.clients[uri] = cli
		return cli
	}
}

func (s *nudrService) SendAuthSubsDataGet(uri string,
	supi string,
) (*models.AuthenticationSubscription, *models.ProblemDetails, error) {
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return nil, nil, err
	}

	req := &Nudr_DataRepository.QueryAuthSubsDataRequest{
		UeId: &supi,
	}
	res, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(ctx, req)
	if err == nil {
		return &res.AuthenticationSubscription, nil, nil
	} else {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, err
	}
}

func (s *nudrService) ModifyAuthenticationPatch(uri string,
	supi string, patchItemArray []models.PatchItem,
) (*models.ProblemDetails, error) {
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return nil, err
	}

	req := &Nudr_DataRepository.ModifyAuthenticationSubscriptionRequest{
		UeId:      &supi,
		PatchItem: patchItemArray,
	}
	_, err = client.AuthenticationSubscriptionDocumentApi.ModifyAuthenticationSubscription(ctx, req)

	if err == nil {
		return nil, nil
	} else {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return &problem, nil
		}
		pd := models.ProblemDetails{Detail: err.Error()}
		return &pd, nil
	}
}

func (s *nudrService) CreateSCPClientToUDR(id string) (*Nudr_DataRepository.APIClient, error) {
	uri := scp_context.GetSelf().UdrUri

	s.mu.RLock()
	client, ok := s.clients[uri]
	if ok {
		s.mu.RUnlock()
		return client, nil
	}

	cfg := Nudr_DataRepository.NewConfiguration()
	cfg.SetBasePath(uri)
	client = Nudr_DataRepository.NewAPIClient(cfg)

	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[uri] = client
	return client, nil
}
