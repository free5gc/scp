package consumer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/free5gc/openapi/models"
	nrfNFDisc "github.com/free5gc/openapi/nrf/NFDisc"
	nrfNFMgmt "github.com/free5gc/openapi/nrf/NFMgmt"
	"github.com/free5gc/scp/internal/logger"
)

const RetryRegisterNrfDuration = 2 * time.Second

var serviceNfType = map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFType{
	models.Nrf_NFMgmt_ServiceName_NNRF_NFM:                  models.Nrf_NFMgmt_NFType_NRF,
	models.Nrf_NFMgmt_ServiceName_NNRF_DISC:                 models.Nrf_NFMgmt_NFType_NRF,
	models.Nrf_NFMgmt_ServiceName_NUDM_SDM:                  models.Nrf_NFMgmt_NFType_UDM,
	models.Nrf_NFMgmt_ServiceName_NUDM_UECM:                 models.Nrf_NFMgmt_NFType_UDM,
	models.Nrf_NFMgmt_ServiceName_NUDM_UEAU:                 models.Nrf_NFMgmt_NFType_UDM,
	models.Nrf_NFMgmt_ServiceName_NUDM_EE:                   models.Nrf_NFMgmt_NFType_UDM,
	models.Nrf_NFMgmt_ServiceName_NUDM_PP:                   models.Nrf_NFMgmt_NFType_UDM,
	models.Nrf_NFMgmt_ServiceName_NAMF_COMM:                 models.Nrf_NFMgmt_NFType_AMF,
	models.Nrf_NFMgmt_ServiceName_NAMF_EVTS:                 models.Nrf_NFMgmt_NFType_AMF,
	models.Nrf_NFMgmt_ServiceName_NAMF_MT:                   models.Nrf_NFMgmt_NFType_AMF,
	models.Nrf_NFMgmt_ServiceName_NAMF_LOC:                  models.Nrf_NFMgmt_NFType_AMF,
	models.Nrf_NFMgmt_ServiceName_NSMF_PDUSESSION:           models.Nrf_NFMgmt_NFType_SMF,
	models.Nrf_NFMgmt_ServiceName_NSMF_EVENT_EXPOSURE:       models.Nrf_NFMgmt_NFType_SMF,
	models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH:                models.Nrf_NFMgmt_NFType_AUSF,
	models.Nrf_NFMgmt_ServiceName_NAUSF_SORPROTECTION:       models.Nrf_NFMgmt_NFType_AUSF,
	models.Nrf_NFMgmt_ServiceName_NAUSF_UPUPROTECTION:       models.Nrf_NFMgmt_NFType_AUSF,
	models.Nrf_NFMgmt_ServiceName_NNEF_PFDMANAGEMENT:        models.Nrf_NFMgmt_NFType_NEF,
	models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL:    models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NPCF_SMPOLICYCONTROL:      models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NPCF_POLICYAUTHORIZATION:  models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NPCF_BDTPOLICYCONTROL:     models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NPCF_EVENTEXPOSURE:        models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NPCF_UE_POLICY_CONTROL:    models.Nrf_NFMgmt_NFType_PCF,
	models.Nrf_NFMgmt_ServiceName_NSMSF_SMS:                 models.Nrf_NFMgmt_NFType_SMSF,
	models.Nrf_NFMgmt_ServiceName_NNSSF_NSSELECTION:         models.Nrf_NFMgmt_NFType_NSSF,
	models.Nrf_NFMgmt_ServiceName_NNSSF_NSSAIAVAILABILITY:   models.Nrf_NFMgmt_NFType_NSSF,
	models.Nrf_NFMgmt_ServiceName_NUDR_DR:                   models.Nrf_NFMgmt_NFType_UDR,
	models.Nrf_NFMgmt_ServiceName_NLMF_LOC:                  models.Nrf_NFMgmt_NFType_LMF,
	models.Nrf_NFMgmt_ServiceName_N5G_EIR_EIC:               models.Nrf_NFMgmt_NFType_5_G_EIR,
	models.Nrf_NFMgmt_ServiceName_NBSF_MANAGEMENT:           models.Nrf_NFMgmt_NFType_BSF,
	models.Nrf_NFMgmt_ServiceName_NCHF_SPENDINGLIMITCONTROL: models.Nrf_NFMgmt_NFType_CHF,
	models.Nrf_NFMgmt_ServiceName_NCHF_CONVERGEDCHARGING:    models.Nrf_NFMgmt_NFType_CHF,
	models.Nrf_NFMgmt_ServiceName_NNWDAF_EVENTSSUBSCRIPTION: models.Nrf_NFMgmt_NFType_NWDAF,
	models.Nrf_NFMgmt_ServiceName_NNWDAF_ANALYTICSINFO:      models.Nrf_NFMgmt_NFType_NWDAF,
}

type nnrfService struct {
	consumer *Consumer

	nfDiscMu        sync.RWMutex
	nfDiscClients   map[string]*nrfNFDisc.APIClient
	nfMngmntMu      sync.RWMutex
	nfMngmntClients map[string]*nrfNFMgmt.APIClient
}

func (s *nnrfService) getNFDiscoveryClient(uri string) *nrfNFDisc.APIClient {
	s.nfDiscMu.RLock()
	client := s.nfDiscClients[uri]
	s.nfDiscMu.RUnlock()
	if client != nil {
		return client
	}
	cfg := nrfNFDisc.NewConfiguration()
	cfg.SetBasePath(uri)
	client = nrfNFDisc.NewAPIClient(cfg)
	s.nfDiscMu.Lock()
	if existing := s.nfDiscClients[uri]; existing != nil {
		client = existing
	} else {
		s.nfDiscClients[uri] = client
	}
	s.nfDiscMu.Unlock()
	return client
}

func (s *nnrfService) getNFManagementClient(uri string) *nrfNFMgmt.APIClient {
	s.nfMngmntMu.RLock()
	client := s.nfMngmntClients[uri]
	s.nfMngmntMu.RUnlock()
	if client != nil {
		return client
	}
	cfg := nrfNFMgmt.NewConfiguration()
	cfg.SetBasePath(uri)
	client = nrfNFMgmt.NewAPIClient(cfg)
	s.nfMngmntMu.Lock()
	if existing := s.nfMngmntClients[uri]; existing != nil {
		client = existing
	} else {
		s.nfMngmntClients[uri] = client
	}
	s.nfMngmntMu.Unlock()
	return client
}

func (s *nnrfService) RegisterNFInstance(ctx context.Context) error {
	client := s.getNFManagementClient(s.consumer.Config().NrfUri())
	nfProfile, err := s.buildNfProfile()
	if err != nil {
		return fmt.Errorf("register NF instance: %w", err)
	}

	for {
		instanceID := s.consumer.Context().NfInstID()
		rsp, requestErr := client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx,
			&nrfNFMgmt.RegisterNFInstanceRequest{NfInstanceID: &instanceID, RequestBody: nfProfile})
		if requestErr == nil {
			if rsp == nil {
				return nilResponse("NRF registration")
			}
			if rsp.Nrf_NFMgmt_NFProfile != nil {
				nfProfile = rsp.Nrf_NFMgmt_NFProfile
			}
			if rsp.Location != "" {
				resourceURI, parseErr := url.Parse(rsp.Location)
				if parseErr != nil {
					return fmt.Errorf("invalid NRF Location %q: %w", rsp.Location, parseErr)
				}
				if id := resourceURI.Path[stringsLastSlash(resourceURI.Path):]; id != "" {
					s.consumer.Context().SetNfInstID(id)
				}
				logger.ConsumerLog.Infof("NFRegister Created")
			} else {
				logger.ConsumerLog.Infof("NFRegister Updated")
			}
			s.applyOAuthSetting(nfProfile)
			return nil
		}

		normalized := normalizeError(requestErr)
		var downstream *DownstreamError
		if errors.As(normalized, &downstream) && downstream.Status >= 400 && downstream.Status < 500 {
			return normalized
		}
		logger.ConsumerLog.Infof("SCP register to NRF failed [%v], retrying", requestErr)
		timer := time.NewTimer(RetryRegisterNrfDuration)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func stringsLastSlash(path string) int {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return i + 1
		}
	}
	return 0
}

func (s *nnrfService) applyOAuthSetting(profile *models.Nrf_NFMgmt_NFProfile) {
	required := false
	if profile != nil && profile.CustomInfo != nil {
		if customInfo, ok := profile.CustomInfo.(map[string]interface{}); ok {
			required, _ = customInfo["oauth2"].(bool)
		}
	}
	s.consumer.Context().SetOAuth2Required(required)
	logger.MainLog.Infoln("OAuth2 setting received from NRF:", required)
	if required && s.consumer.Config().NrfCertPem() == "" {
		logger.CfgLog.Error("OAuth2 enabled but no nrfCertPem is configured")
	}
}

func (s *nnrfService) buildNfProfile() (*models.Nrf_NFMgmt_NFProfile, error) {
	profile := &models.Nrf_NFMgmt_NFProfile{
		NfInstanceId:  s.consumer.Context().NfInstID(),
		NfType:        models.Nrf_NFMgmt_NFType_SCP,
		NfStatus:      models.Nrf_NFMgmt_NFStatus_REGISTERED,
		Ipv4Addresses: []string{s.consumer.Config().SbiRegisterIP()},
		NfServices:    s.consumer.Config().NFServices(),
	}
	if len(profile.NfServices) == 0 {
		return nil, fmt.Errorf("NFServices is empty")
	}
	return profile, nil
}

func (s *nnrfService) DeregisterNFInstance(parent context.Context) error {
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NNRF_NFM, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return err
	}
	client := s.getNFManagementClient(s.consumer.Config().NrfUri())
	instanceID := s.consumer.Context().NfInstID()
	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx,
		&nrfNFMgmt.DeregisterNFInstanceRequest{NfInstanceID: &instanceID})
	return normalizeError(err)
}

func (s *nnrfService) SearchNFInstances(
	parent context.Context,
	nrfURI string,
	serviceName models.Nrf_NFMgmt_ServiceName,
	request *nrfNFDisc.SearchNFInstancesRequest,
) (*models.Nrf_NFDisc_NFProfile, string, error) {
	if request == nil {
		request = &nrfNFDisc.SearchNFInstancesRequest{}
	}
	targetType, ok := serviceNfType[serviceName]
	if !ok {
		return nil, "", fmt.Errorf("no target NF type for service %s", serviceName)
	}
	request.ServiceNames = []models.Nrf_NFMgmt_ServiceName{serviceName}
	request.TargetNfType = &targetType
	requesterType := models.Nrf_NFMgmt_NFType_SCP
	request.RequesterNfType = &requesterType
	ctx, _, err := s.consumer.Context().GetTokenCtx(parent,
		models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return nil, "", err
	}
	rsp, err := s.getNFDiscoveryClient(nrfURI).NFInstancesStoreApi.SearchNFInstances(ctx, request)
	if err != nil {
		return nil, "", normalizeError(err)
	}
	if rsp == nil || rsp.Nrf_NFDisc_SearchResult == nil {
		return nil, "", nilResponse("NRF discovery")
	}
	return getProfileAndURI(rsp.Nrf_NFDisc_SearchResult.NfInstances, serviceName)
}

func getProfileAndURI(
	instances []models.Nrf_NFDisc_NFProfile,
	serviceName models.Nrf_NFMgmt_ServiceName,
) (*models.Nrf_NFDisc_NFProfile, string, error) {
	for i := range instances {
		if uri := searchNFServiceURI(instances[i], serviceName, models.Nrf_NFMgmt_NFServiceStatus_REGISTERED); uri != "" {
			return &instances[i], uri, nil
		}
	}
	return nil, "", fmt.Errorf("no URI for %s found", serviceName)
}

func searchNFServiceURI(
	profile models.Nrf_NFDisc_NFProfile,
	serviceName models.Nrf_NFMgmt_ServiceName,
	status models.Nrf_NFMgmt_NFServiceStatus,
) string {
	for _, service := range profile.NfServices {
		if service.ServiceName != serviceName || service.NfServiceStatus != status {
			continue
		}
		if service.Fqdn != "" {
			return string(service.Scheme) + "://" + service.Fqdn
		}
		if profile.Fqdn != "" {
			return string(service.Scheme) + "://" + profile.Fqdn
		}
		if service.ApiPrefix != "" {
			if parsed, err := url.Parse(service.ApiPrefix); err == nil {
				return parsed.Scheme + "://" + parsed.Host
			}
		}
		if len(service.IpEndPoints) > 0 {
			point := service.IpEndPoints[0]
			address := point.Ipv4Address
			if address == "" && len(profile.Ipv4Addresses) > 0 {
				address = profile.Ipv4Addresses[0]
			}
			if address != "" {
				return uriFromIPEndpoint(service.Scheme, address, point.Port)
			}
		}
	}
	return ""
}

func uriFromIPEndpoint(scheme models.UriScheme, address string, port int32) string {
	if port != 0 {
		return string(scheme) + "://" + address + ":" + strconv.Itoa(int(port))
	}
	if scheme == models.UriScheme_HTTP {
		return string(scheme) + "://" + address + ":80"
	}
	if scheme == models.UriScheme_HTTPS {
		return string(scheme) + "://" + address + ":443"
	}
	return ""
}
