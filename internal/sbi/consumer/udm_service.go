package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	Nudm_UEAU "github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
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
	supiOrSuci string, authInfoReq *models.AuthenticationInfoRequest,
) (*models.AuthenticationInfoResult, *models.ProblemDetails, error) {
	client := s.getUdmUeauClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDM_UEAU, models.NfType_UDM)
	if err != nil {
		return nil, nil, err
	}

	authInfoResult, httpResponse, err := client.GenerateAuthDataApi.GenerateAuthData(ctx, supiOrSuci, *authInfoReq)
	if err == nil {
		return &authInfoResult, nil, nil
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
