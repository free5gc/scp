package consumer

import (
	"sync"

	"github.com/free5gc/openapi"
	Nausf_UEAuthentication "github.com/free5gc/openapi/ausf/UEAuthentication"
	"github.com/free5gc/openapi/models"
)

type nausfService struct {
	consumer *Consumer

	UEAuthenticationMu sync.RWMutex

	UEAuthenticationClients map[string]*Nausf_UEAuthentication.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *Nausf_UEAuthentication.APIClient {
	if uri == "" {
		return nil
	}
	s.UEAuthenticationMu.RLock()
	client, ok := s.UEAuthenticationClients[uri]
	if ok {
		s.UEAuthenticationMu.RUnlock()
		return client
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nausf_UEAuthentication.NewAPIClient(configuration)

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

	req := &Nausf_UEAuthentication.UeAuthenticationsPostRequest{
		AuthenticationInfo: authInfo,
	}
	res, err := client.DefaultApi.UeAuthenticationsPost(ctx, req)
	if err == nil {
		return &res.UeAuthenticationCtx, nil, nil
	} else {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, err
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

	req := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutRequest{
		AuthCtxId:        &authCtxId,
		ConfirmationData: confirmationData,
	}
	res, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(ctx, req)
	if err == nil {
		return &res.ConfirmationDataResponse, nil, nil
	} else {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, err
	}
}

func (s *nausfService) SendEapAuthConfirmRequest(uri string,
	authCtxId string, eapSessionReq *models.EapSession,
) (*models.EapSession, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(uri)

	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	req := &Nausf_UEAuthentication.EapAuthMethodRequest{
		AuthCtxId:  &authCtxId,
		EapSession: eapSessionReq,
	}
	res, err := client.DefaultApi.EapAuthMethod(ctx, req)
	if err == nil {
		return &res.EapSession, nil, nil
	} else {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			problem := apiErr.Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, err
	}
}
