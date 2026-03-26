package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

const (
	RetryRegisterNrfDuration = 2 * time.Second
)

var serviceNfType map[models.ServiceName]models.NFType

func init() {
	serviceNfType = make(map[models.ServiceName]models.NFType)
	serviceNfType[models.ServiceName_NNRF_NFM] = models.NFType_NRF
	serviceNfType[models.ServiceName_NNRF_DISC] = models.NFType_NRF
	serviceNfType[models.ServiceName_NUDM_SDM] = models.NFType_UDM
	serviceNfType[models.ServiceName_NUDM_UECM] = models.NFType_UDM
	serviceNfType[models.ServiceName_NUDM_UEAU] = models.NFType_UDM
	serviceNfType[models.ServiceName_NUDM_EE] = models.NFType_UDM
	serviceNfType[models.ServiceName_NUDM_PP] = models.NFType_UDM
	serviceNfType[models.ServiceName_NAMF_COMM] = models.NFType_AMF
	serviceNfType[models.ServiceName_NAMF_EVTS] = models.NFType_AMF
	serviceNfType[models.ServiceName_NAMF_MT] = models.NFType_AMF
	serviceNfType[models.ServiceName_NAMF_LOC] = models.NFType_AMF
	serviceNfType[models.ServiceName_NSMF_PDUSESSION] = models.NFType_SMF
	serviceNfType[models.ServiceName_NSMF_EVENT_EXPOSURE] = models.NFType_SMF
	serviceNfType[models.ServiceName_NAUSF_AUTH] = models.NFType_AUSF
	serviceNfType[models.ServiceName_NAUSF_SORPROTECTION] = models.NFType_AUSF
	serviceNfType[models.ServiceName_NAUSF_UPUPROTECTION] = models.NFType_AUSF
	serviceNfType[models.ServiceName_NNEF_PFDMANAGEMENT] = models.NFType_NEF
	serviceNfType[models.ServiceName_NPCF_AM_POLICY_CONTROL] = models.NFType_PCF
	serviceNfType[models.ServiceName_NPCF_SMPOLICYCONTROL] = models.NFType_PCF
	serviceNfType[models.ServiceName_NPCF_POLICYAUTHORIZATION] = models.NFType_PCF
	serviceNfType[models.ServiceName_NPCF_BDTPOLICYCONTROL] = models.NFType_PCF
	serviceNfType[models.ServiceName_NPCF_EVENTEXPOSURE] = models.NFType_PCF
	serviceNfType[models.ServiceName_NPCF_UE_POLICY_CONTROL] = models.NFType_PCF
	serviceNfType[models.ServiceName_NSMSF_SMS] = models.NFType_SMSF
	serviceNfType[models.ServiceName_NNSSF_NSSELECTION] = models.NFType_NSSF
	serviceNfType[models.ServiceName_NNSSF_NSSAIAVAILABILITY] = models.NFType_NSSF
	serviceNfType[models.ServiceName_NUDR_DR] = models.NFType_UDR
	serviceNfType[models.ServiceName_NLMF_LOC] = models.NFType_LMF
	serviceNfType[models.ServiceName_N5G_EIR_EIC] = models.NFType_5_G_EIR
	serviceNfType[models.ServiceName_NBSF_MANAGEMENT] = models.NFType_BSF
	serviceNfType[models.ServiceName_NCHF_SPENDINGLIMITCONTROL] = models.NFType_CHF
	serviceNfType[models.ServiceName_NCHF_CONVERGEDCHARGING] = models.NFType_CHF
	serviceNfType[models.ServiceName_NNWDAF_EVENTSSUBSCRIPTION] = models.NFType_NWDAF
	serviceNfType[models.ServiceName_NNWDAF_ANALYTICSINFO] = models.NFType_NWDAF
}

type nnrfService struct {
	consumer *Consumer

	nfDiscMu      sync.RWMutex
	nfDiscClients map[string]*Nnrf_NFDiscovery.APIClient

	nfMngmntMu      sync.RWMutex
	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
}

func (s *nnrfService) getNFDiscoveryClient(uri string) *Nnrf_NFDiscovery.APIClient {
	s.nfDiscMu.RLock()
	if client, ok := s.nfDiscClients[uri]; ok {
		defer s.nfDiscMu.RUnlock()
		return client
	} else {
		configuration := Nnrf_NFDiscovery.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := Nnrf_NFDiscovery.NewAPIClient(configuration)

		s.nfDiscMu.RUnlock()
		s.nfDiscMu.Lock()
		defer s.nfDiscMu.Unlock()
		s.nfDiscClients[uri] = cli
		return cli
	}
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	s.nfMngmntMu.RLock()
	if client, ok := s.nfMngmntClients[uri]; ok {
		defer s.nfMngmntMu.RUnlock()
		return client
	} else {
		configuration := Nnrf_NFManagement.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := Nnrf_NFManagement.NewAPIClient(configuration)

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
		req := &Nnrf_NFManagement.RegisterNFInstanceRequest{
			NfInstanceID:             &nfInstID,
			NrfNfManagementNfProfile: nfProfile,
		}
		res, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), req)

		if err != nil {
			logger.ConsumerLog.Infof("SCP register to NRF Error[%v], sleep 2s and retry", err)
			time.Sleep(RetryRegisterNrfDuration)
			continue
		}

		nf = res.NrfNfManagementNfProfile
		status := http.StatusCreated
		if res.Location == "" {
			status = http.StatusOK
		}

		if status == http.StatusOK {
			// NFUpdate
			logger.ConsumerLog.Infof("NFRegister Update")
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.Location
			// resouceNrfUri := resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			nfInstID := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
			s.consumer.Context().SetNfInstID(nfInstID)

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
	req := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &nfInstID,
	}
	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, req)

	if err != nil {
		pd := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return fmt.Errorf("DeregisterNFInstance Failed: Problem[%+v]", pd)
	}
	return nil
}

func (s *nnrfService) SearchNFInstances(
	nrfUri string,
	srvName models.ServiceName,
	param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (*models.NrfNfManagementNfProfile, string, error) {
	if param == nil {
		param = &Nnrf_NFDiscovery.SearchNFInstancesRequest{}
	}
	param.ServiceNames = []models.ServiceName{srvName}

	client := s.getNFDiscoveryClient(nrfUri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return nil, "", err
	}

	targetNfType := models.NrfNfManagementNfType(serviceNfType[srvName])
	requesterNfType := models.NrfNfManagementNfType_SCP
	param.TargetNfType = &targetNfType
	param.RequesterNfType = &requesterNfType

	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, param)

	if err != nil {
		return nil, "", err
	}

	nfProf, uri, err := getProfileAndUri(res.SearchResult.NfInstances, srvName)
	if err != nil {
		logger.ConsumerLog.Errorf("%+v", err)
		return nil, "", err
	}
	return nfProf, uri, nil
}

func getProfileAndUri(nfInstances []models.NrfNfDiscoveryNfProfile, srvName models.ServiceName) (*models.NrfNfManagementNfProfile, string, error) {
	// select the first ServiceName
	// TODO: select base on other info
	var profile *models.NrfNfManagementNfProfile
	var uri string
	for _, nfProfile := range nfInstances {
		b, err := json.Marshal(nfProfile)
		if err != nil {
			continue
		}
		var mProfile models.NrfNfManagementNfProfile
		err = json.Unmarshal(b, &mProfile)
		if err != nil {
			continue
		}
		profile = &mProfile
		uri = searchNFServiceUri(*profile, srvName, models.NfServiceStatus_REGISTERED)
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
func searchNFServiceUri(nfProfile models.NrfNfManagementNfProfile, serviceName models.ServiceName,
	nfServiceStatus models.NfServiceStatus,
) string {
	if len(nfProfile.NfServices) == 0 {
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
				point := service.IpEndPoints[0]
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
