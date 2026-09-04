package consumer

import (
	"context"
	"sync"

	ausfUEAU "github.com/free5gc/openapi/ausf/UEAU"
	"github.com/free5gc/openapi/models"
)

type nausfService struct {
	consumer *Consumer
	mu       sync.RWMutex
	clients  map[string]*ausfUEAU.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *ausfUEAU.APIClient {
	if uri == "" {
		return nil
	}
	s.mu.RLock()
	client := s.clients[uri]
	s.mu.RUnlock()
	if client != nil {
		return client
	}
	cfg := ausfUEAU.NewConfiguration()
	cfg.SetBasePath(uri)
	client = ausfUEAU.NewAPIClient(cfg)
	s.mu.Lock()
	if existing := s.clients[uri]; existing != nil {
		client = existing
	} else {
		s.clients[uri] = client
	}
	s.mu.Unlock()
	return client
}

func (s *nausfService) SendUeAuthPostRequest(
	parent context.Context,
	uri string,
	authInfo models.Ausf_UEAU_AuthenticationInfo,
) (*models.Ausf_UEAU_UEAuthenticationCtx, error) {
	client := s.getUEAuthenticationClient(uri)
	if client == nil {
		return nil, nilResponse("AUSF authentication")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF)
	if err != nil {
		return nil, err
	}
	rsp, err := client.DefaultApi.UeAuthenticationsPost(ctx, &ausfUEAU.UeAuthenticationsPostRequest{
		RequestBody: &authInfo,
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil || rsp.Ausf_UEAU_UEAuthenticationCtx == nil {
		return nil, nilResponse("AUSF authentication")
	}
	return rsp.Ausf_UEAU_UEAuthenticationCtx, nil
}

func (s *nausfService) SendAuth5gAkaConfirmRequest(
	parent context.Context,
	uri, authCtxID string,
	confirmationData *models.Ausf_UEAU_ConfirmationData,
) (*models.Ausf_UEAU_ConfirmationDataResponse, error) {
	client := s.getUEAuthenticationClient(uri)
	if client == nil {
		return nil, nilResponse("AUSF 5G AKA confirmation")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF)
	if err != nil {
		return nil, err
	}
	rsp, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(ctx,
		&ausfUEAU.UeAuthenticationsAuthCtxId5gAkaConfirmationPutRequest{
			AuthCtxId: &authCtxID, RequestBody: confirmationData,
		})
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil || rsp.Ausf_UEAU_ConfirmationDataResponse == nil {
		return nil, nilResponse("AUSF 5G AKA confirmation")
	}
	return rsp.Ausf_UEAU_ConfirmationDataResponse, nil
}

func (s *nausfService) SendEapAuthConfirmRequest(
	parent context.Context,
	uri, authCtxID string,
	eapSession *models.Ausf_UEAU_EapSession,
) (*models.Ausf_UEAU_EapSession, error) {
	client := s.getUEAuthenticationClient(uri)
	if client == nil {
		return nil, nilResponse("AUSF EAP confirmation")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, models.Nrf_NFMgmt_NFType_AUSF)
	if err != nil {
		return nil, err
	}
	rsp, err := client.DefaultApi.EapAuthMethod(ctx, &ausfUEAU.EapAuthMethodRequest{
		AuthCtxId: &authCtxID, RequestBody: eapSession,
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil || rsp.Ausf_UEAU_EapSession == nil {
		return nil, nilResponse("AUSF EAP confirmation")
	}
	return rsp.Ausf_UEAU_EapSession, nil
}
