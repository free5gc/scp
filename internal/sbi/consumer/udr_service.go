package consumer

import (
	"context"
	"sync"

	"github.com/free5gc/openapi/models"
	udrDR "github.com/free5gc/openapi/udr/DR"
)

type nudrService struct {
	consumer *Consumer
	mu       sync.RWMutex
	clients  map[string]*udrDR.APIClient
}

func (s *nudrService) getClient(uri string) *udrDR.APIClient {
	if uri == "" {
		return nil
	}
	s.mu.RLock()
	client := s.clients[uri]
	s.mu.RUnlock()
	if client != nil {
		return client
	}
	cfg := udrDR.NewConfiguration()
	cfg.SetBasePath(uri)
	client = udrDR.NewAPIClient(cfg)
	s.mu.Lock()
	if existing := s.clients[uri]; existing != nil {
		client = existing
	} else {
		s.clients[uri] = client
	}
	s.mu.Unlock()
	return client
}

func (s *nudrService) SendAuthSubsDataGet(
	parent context.Context, uri, supi string, supportedFeatures *string,
) (*models.Udr_DR_AuthenticationSubscription, error) {
	client := s.getClient(uri)
	if client == nil {
		return nil, nilResponse("UDR query authentication subscription")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NUDR_DR, models.Nrf_NFMgmt_NFType_UDR)
	if err != nil {
		return nil, err
	}
	rsp, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(ctx,
		&udrDR.QueryAuthSubsDataRequest{UeId: &supi, SupportedFeatures: supportedFeatures})
	if err != nil {
		return nil, normalizeError(err)
	}
	if rsp == nil || rsp.Udr_DR_AuthenticationSubscription == nil {
		return nil, nilResponse("UDR query authentication subscription")
	}
	return rsp.Udr_DR_AuthenticationSubscription, nil
}

func (s *nudrService) ModifyAuthenticationPatch(
	parent context.Context, uri, supi string, patches []models.PatchItem, supportedFeatures *string,
) error {
	client := s.getClient(uri)
	if client == nil {
		return nilResponse("UDR modify authentication subscription")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NUDR_DR, models.Nrf_NFMgmt_NFType_UDR)
	if err != nil {
		return err
	}
	_, err = client.AuthenticationSubscriptionDocumentApi.ModifyAuthenticationSubscription(ctx,
		&udrDR.ModifyAuthenticationSubscriptionRequest{
			UeId: &supi, RequestBody: patches, SupportedFeatures: supportedFeatures,
		})
	return normalizeError(err)
}

func (s *nudrService) CreateAuthenticationStatus(
	parent context.Context, uri, supi string, authEvent *models.Udm_UEAU_AuthEvent,
) error {
	client := s.getClient(uri)
	if client == nil {
		return nilResponse("UDR create authentication status")
	}
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NUDR_DR, models.Nrf_NFMgmt_NFType_UDR)
	if err != nil {
		return err
	}
	_, err = client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(ctx,
		&udrDR.CreateAuthenticationStatusRequest{UeId: &supi, RequestBody: authEvent})
	return normalizeError(err)
}
