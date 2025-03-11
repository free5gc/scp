package consumer

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDiscovery"
	"github.com/free5gc/openapi/nrf/NFManagement"
	"github.com/free5gc/scp/internal/logger"
)

const (
	RetryRegisterNrfDuration = 2 * time.Second
)

var serviceNfType map[models.ServiceName]models.NrfNfManagementNfType

func init() {
	serviceNfType = make(map[models.ServiceName]models.NrfNfManagementNfType)
	serviceNfType[models.ServiceName_NNRF_NFM] = models.NrfNfManagementNfType_NRF
	serviceNfType[models.ServiceName_NNRF_DISC] = models.NrfNfManagementNfType_NRF
	serviceNfType[models.ServiceName_NUDM_SDM] = models.NrfNfManagementNfType_UDM
	serviceNfType[models.ServiceName_NUDM_UECM] = models.NrfNfManagementNfType_UDM
	serviceNfType[models.ServiceName_NUDM_UEAU] = models.NrfNfManagementNfType_UDM
	serviceNfType[models.ServiceName_NUDM_EE] = models.NrfNfManagementNfType_UDM
	serviceNfType[models.ServiceName_NUDM_PP] = models.NrfNfManagementNfType_UDM
	serviceNfType[models.ServiceName_NAMF_COMM] = models.NrfNfManagementNfType_AMF
	serviceNfType[models.ServiceName_NAMF_EVTS] = models.NrfNfManagementNfType_AMF
	serviceNfType[models.ServiceName_NAMF_MT] = models.NrfNfManagementNfType_AMF
	serviceNfType[models.ServiceName_NAMF_LOC] = models.NrfNfManagementNfType_AMF
	serviceNfType[models.ServiceName_NSMF_PDUSESSION] = models.NrfNfManagementNfType_SMF
	serviceNfType[models.ServiceName_NSMF_EVENT_EXPOSURE] = models.NrfNfManagementNfType_SMF
	serviceNfType[models.ServiceName_NAUSF_AUTH] = models.NrfNfManagementNfType_AUSF
	serviceNfType[models.ServiceName_NAUSF_SORPROTECTION] = models.NrfNfManagementNfType_AUSF
	serviceNfType[models.ServiceName_NAUSF_UPUPROTECTION] = models.NrfNfManagementNfType_AUSF
	serviceNfType[models.ServiceName_NNEF_PFDMANAGEMENT] = models.NrfNfManagementNfType_NEF
	serviceNfType[models.ServiceName_NPCF_AM_POLICY_CONTROL] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NPCF_SMPOLICYCONTROL] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NPCF_POLICYAUTHORIZATION] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NPCF_BDTPOLICYCONTROL] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NPCF_EVENTEXPOSURE] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NPCF_UE_POLICY_CONTROL] = models.NrfNfManagementNfType_PCF
	serviceNfType[models.ServiceName_NSMSF_SMS] = models.NrfNfManagementNfType_SMSF
	serviceNfType[models.ServiceName_NNSSF_NSSELECTION] = models.NrfNfManagementNfType_NSSF
	serviceNfType[models.ServiceName_NNSSF_NSSAIAVAILABILITY] = models.NrfNfManagementNfType_NSSF
	serviceNfType[models.ServiceName_NUDR_DR] = models.NrfNfManagementNfType_UDR
	serviceNfType[models.ServiceName_NLMF_LOC] = models.NrfNfManagementNfType_LMF
	serviceNfType[models.ServiceName_N5G_EIR_EIC] = models.NrfNfManagementNfType__5_G_EIR
	serviceNfType[models.ServiceName_NBSF_MANAGEMENT] = models.NrfNfManagementNfType_BSF
	serviceNfType[models.ServiceName_NCHF_SPENDINGLIMITCONTROL] = models.NrfNfManagementNfType_CHF
	serviceNfType[models.ServiceName_NCHF_CONVERGEDCHARGING] = models.NrfNfManagementNfType_CHF
	serviceNfType[models.ServiceName_NNWDAF_EVENTSSUBSCRIPTION] = models.NrfNfManagementNfType_NWDAF
	serviceNfType[models.ServiceName_NNWDAF_ANALYTICSINFO] = models.NrfNfManagementNfType_NWDAF
}

type nnrfService struct {
	consumer *Consumer

	nfDiscMu      sync.RWMutex
	nfDiscClients map[string]*NFDiscovery.APIClient

	nfMngmntMu      sync.RWMutex
	nfMngmntClients map[string]*NFManagement.APIClient
}

func (s *nnrfService) getNFDiscoveryClient(uri string) *NFDiscovery.APIClient {
	s.nfDiscMu.RLock()
	if client, ok := s.nfDiscClients[uri]; ok {
		defer s.nfDiscMu.RUnlock()
		return client
	} else {
		configuration := NFDiscovery.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := NFDiscovery.NewAPIClient(configuration)

		s.nfDiscMu.RUnlock()
		s.nfDiscMu.Lock()
		defer s.nfDiscMu.Unlock()
		s.nfDiscClients[uri] = cli
		return cli
	}
}

func (s *nnrfService) getNFManagementClient(uri string) *NFManagement.APIClient {
	s.nfMngmntMu.RLock()
	if client, ok := s.nfMngmntClients[uri]; ok {
		defer s.nfMngmntMu.RUnlock()
		return client
	} else {
		configuration := NFManagement.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := NFManagement.NewAPIClient(configuration)

		s.nfMngmntMu.RUnlock()
		s.nfMngmntMu.Lock()
		defer s.nfMngmntMu.Unlock()
		s.nfMngmntClients[uri] = cli
		return cli
	}
}

func (s *nnrfService) RegisterNFInstance() error {
	var nf models.NrfNfManagementNfProfile
	var err error

	client := s.getNFManagementClient(s.consumer.Config().NrfUri())
	nfProfile, err := s.buildNfProfile()
	if err != nil {
		return fmt.Errorf("RegisterNFInstance err: %+v", err)
	}

	for {
		nfInstID := s.consumer.Context().NfInstID()
		nfInstIDPtr := &nfInstID
		registerNFInstanceReq := NFManagement.RegisterNFInstanceRequest{
			NfInstanceID:             nfInstIDPtr,
			NrfNfManagementNfProfile: nfProfile,
		}

		rsp, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), &registerNFInstanceReq)
		if err != nil {
			logger.ConsumerLog.Infof("SCP register to NRF Error[%v], sleep 2s and retry", err)
			time.Sleep(RetryRegisterNrfDuration)
			continue
		}

		// 根據返回的狀態碼進行處理
		if rsp.ETag != "" {
			// NFUpdate
			logger.ConsumerLog.Infof("NFRegister Update")
			break
		} else if rsp.Location != "" {
			// NFRegister
			resourceUri := rsp.Location
			s.consumer.Context().SetNfInstID(resourceUri[strings.LastIndex(resourceUri, "/")+1:])

			oauth2 := false
			if nf.CustomInfo != nil {
				v, ok := nf.CustomInfo["oauth2"].(bool)
				if ok {
					oauth2 = v
					logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
				}
			}
			s.consumer.Context().OAuth2Required = oauth2
			if oauth2 && s.consumer.Context().Config().NrfCertPem() == "" {
				logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
			}

			logger.ConsumerLog.Infof("NFRegister Created")
			break
		} else {
			logger.ConsumerLog.Infof("NRF return wrong status")
		}
	}
	return nil
}

func (s *nnrfService) buildNfProfile() (*models.NrfNfManagementNfProfile, error) {
	profile := &models.NrfNfManagementNfProfile{
		NfInstanceId: s.consumer.Context().NfInstID(),
		NfType:       models.NrfNfManagementNfType_SCP,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
	}

	cfg := s.consumer.Config()
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, cfg.SbiRegisterIP())
	nfServices := cfg.NFServices()
	if len(nfServices) == 0 {
		return nil, fmt.Errorf("buildNfProfile err: NFServices is Empty")
	}
	profile.NfServices = nfServices
	return profile, nil
}

func (s *nnrfService) DeregisterNFInstance() error {
	logger.ConsumerLog.Infof("DeregisterNFInstance")

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return nil
	}

	client := s.getNFManagementClient(s.consumer.Config().NrfUri())
	nfInstID := s.consumer.Context().NfInstID()
	nfInstIDPtr := &nfInstID
	deregisterNFInstanceReq := NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: nfInstIDPtr,
	}

	rsp, err := client.NFInstanceIDDocumentApi.DeregisterNFInstance(
		ctx, &deregisterNFInstanceReq)
	if err != nil {
		if rsp == nil {
			return fmt.Errorf("DeregisterNFInstance Error: server no response")
		}
		pd := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return fmt.Errorf("DeregisterNFInstance Failed: Problem[%+v]", pd)
	}
	return nil
}

func (s *nnrfService) SearchNFInstances(
	nrfUri string,
	srvName models.ServiceName,
	param *NFDiscovery.SearchNFInstancesRequest,
) (*models.NrfNfDiscoveryNfProfile, string, error) {
	if param == nil {
		param = &NFDiscovery.SearchNFInstancesRequest{}
	}
	param.ServiceNames = []models.ServiceName{srvName}

	client := s.getNFDiscoveryClient(nrfUri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return nil, "", err
	}
	targetNfType := serviceNfType[srvName]
	requesterNfType := models.NrfNfManagementNfType_SCP
	param.TargetNfType = &targetNfType
	param.RequesterNfType = &requesterNfType

	rsp, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, param)
	if err != nil {
		if rsp != nil {
			logger.DetectorLog.Println("rsp: ", rsp)
		}
		return nil, "", err
	}

	nfProf, uri, err := getProfileAndUri(rsp.SearchResult.NfInstances, srvName)
	if err != nil {
		logger.ConsumerLog.Errorf(err.Error())
		return nil, "", err
	}
	return nfProf, uri, nil
}

func getProfileAndUri(nfInstances []models.NrfNfDiscoveryNfProfile, srvName models.ServiceName) (
	*models.NrfNfDiscoveryNfProfile, string, error,
) {
	// select the first ServiceName
	// TODO: select base on other info
	var profile *models.NrfNfDiscoveryNfProfile
	var uri string
	for _, nfProfile := range nfInstances {
		profile = &nfProfile
		uri = searchNFServiceUri(nfProfile, srvName, models.NfServiceStatus_REGISTERED)
		if uri != "" {
			break
		}
	}
	if uri == "" {
		return nil, "", fmt.Errorf("no uri for %s found", srvName)
	}
	return profile, uri, nil
}

// searchNFServiceUri returns NF Uri derived from NfProfile with corresponding service
func searchNFServiceUri(nfProfile models.NrfNfDiscoveryNfProfile, serviceName models.ServiceName,
	nfServiceStatus models.NfServiceStatus,
) string {
	if nfProfile.NfServices == nil {
		return ""
	}

	nfUri := ""
	for _, service := range nfProfile.NfServices {
		if service.ServiceName == serviceName && service.NfServiceStatus == nfServiceStatus {
			if service.Fqdn != "" {
				nfUri = string(service.Scheme) + "://" + service.Fqdn
			} else if nfProfile.Fqdn != "" {
				nfUri = string(service.Scheme) + "://" + nfProfile.Fqdn
			} else if service.ApiPrefix != "" {
				u, err := url.Parse(service.ApiPrefix)
				if err != nil {
					return nfUri
				}
				nfUri = u.Scheme + "://" + u.Host
			} else if len(service.IpEndPoints) != 0 {
				// Select the first IpEndPoint
				// TODO: select others when failure
				point := (service.IpEndPoints)[0]
				if point.Ipv4Address != "" {
					nfUri = getUriFromIpEndPoint(service.Scheme, point.Ipv4Address, point.Port)
				} else if len(nfProfile.Ipv4Addresses) != 0 {
					nfUri = getUriFromIpEndPoint(service.Scheme, nfProfile.Ipv4Addresses[0], point.Port)
				}
			}
		}
		if nfUri != "" {
			break
		}
	}

	return nfUri
}

func getUriFromIpEndPoint(scheme models.UriScheme, ipv4Address string, port int32) string {
	uri := ""
	if port != 0 {
		uri = string(scheme) + "://" + ipv4Address + ":" + strconv.Itoa(int(port))
	} else {
		switch scheme {
		case models.UriScheme_HTTP:
			uri = string(scheme) + "://" + ipv4Address + ":80"
		case models.UriScheme_HTTPS:
			uri = string(scheme) + "://" + ipv4Address + ":443"
		}
	}
	return uri
}
