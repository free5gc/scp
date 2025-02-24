package consumer

import (
	"sync"

	"github.com/antihax/optional"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/ausf/UEAuthentication"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

type nausfService struct {
	consumer *Consumer

	UEAuthenticationMu sync.RWMutex

	UEAuthenticationClients map[string]*UEAuthentication.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *UEAuthentication.APIClient {
	if uri == "" {
		return nil
	}
	s.UEAuthenticationMu.RLock()
	client, ok := s.UEAuthenticationClients[uri]
	if ok {
		s.UEAuthenticationMu.RUnlock()
		return client
	}

	configuration := UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)
	client = UEAuthentication.NewAPIClient(configuration)

	s.UEAuthenticationMu.RUnlock()
	s.UEAuthenticationMu.Lock()
	defer s.UEAuthenticationMu.Unlock()
	s.UEAuthenticationClients[uri] = client
	return client
}

func (s *nausfService) SendUeAuthPostRequest(uri string,
	authInfo *models.AuthenticationInfo,
) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(uri)

	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	ueAuthenticationCtx, httpResponse, err := client.DefaultApi.UeAuthenticationsPost(ctx, *authInfo)
	if err == nil {
		return &ueAuthenticationCtx, nil, nil
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

func (s *nausfService) SendAuth5gAkaConfirmRequest(uri string,
	authCtxId string, confirmationData *models.ConfirmationData,
) (*models.ConfirmationDataResponse, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(uri)

	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	confirmData := &UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
		ConfirmationData: optional.NewInterface(*confirmationData),
	}

	confirmResult, httpResponse, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		ctx, authCtxId, confirmData)
	if err == nil {
		return &confirmResult, nil, nil
	} else if httpResponse != nil {
		defer func() {
			if closeErr := httpResponse.Body.Close(); closeErr != nil {
				logger.DetectorLog.Warnln("Failed to close response body:", err)
			}
		}()
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func (s *nausfService) SendEapAuthConfirmRequest(uri string,
	authCtxId string, eapSessionReq *models.EapSession,
) (*models.EapSession, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(uri)

	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	eapAuthMethodParamOpts := &UEAuthentication.EapAuthMethodParamOpts{
		EapSession: optional.NewInterface(eapSessionReq),
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	eapSession, httpResponse, err := client.DefaultApi.EapAuthMethod(
		ctx, authCtxId, eapAuthMethodParamOpts)
	if err == nil {
		return &eapSession, nil, nil
	} else if httpResponse != nil {
		defer func() {
			if closeErr := httpResponse.Body.Close(); closeErr != nil {
				logger.DetectorLog.Warnln("Failed to close response body:", err)
			}
		}()
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}
