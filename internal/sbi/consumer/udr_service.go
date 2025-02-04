package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
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

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return nil, nil, err
	}

	authSubs, httpResponse, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(ctx, supi, nil)
	if err == nil {
		return &authSubs, nil, nil
	} else if httpResponse != nil {
		defer func() {
			if closeErr := httpResponse.Body.Close(); closeErr != nil {
				logger.DetectorLog.Warnln("Failed to close response body:", err)
			}
		}()
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func (s *nudrService) ModifyAuthenticationPatch(uri string,
	supi string, patchItemArray []models.PatchItem,
) (*models.ProblemDetails, error) {
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return nil, err
	}

	httpResponse, err := client.AuthenticationDataDocumentApi.ModifyAuthentication(ctx, supi, patchItemArray)

	if err == nil {
		return nil, nil
	} else if httpResponse != nil {
		defer func() {
			if closeErr := httpResponse.Body.Close(); closeErr != nil {
				logger.DetectorLog.Warnln("Failed to close response body:", err)
			}
		}()
		if httpResponse.Status != err.Error() {
			return nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, nil
	} else {
		return nil, openapi.ReportError("server no response")
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
