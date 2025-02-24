package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/ausf/UEAuthentication"
	"github.com/free5gc/openapi/models"
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
	authInfo *UEAuthentication.UeAuthenticationsPostRequest,
) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(uri)

	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	ueAuthPostResp, err := client.DefaultApi.UeAuthenticationsPost(ctx, authInfo)
	if err == nil {
		return &ueAuthPostResp.UeAuthenticationCtx, nil, nil
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

	var confirmData *UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutRequest

	confirmResultResp, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		ctx, confirmData)
	if err == nil {
		return &confirmResultResp.ConfirmationDataResponse, nil, nil
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

	var eapAuthMethodReq *UEAuthentication.EapAuthMethodRequest
	eapAuthMethodReq.EapSession = eapSessionReq
	eapAuthMethodReq.AuthCtxId = &authCtxId

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	eapSessionResp, err := client.DefaultApi.EapAuthMethod(
		ctx, eapAuthMethodReq)
	if err == nil {
		return &eapSessionResp.EapSession, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}
