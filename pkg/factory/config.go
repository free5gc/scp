package factory

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/davecgh/go-spew/spew"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/util/nfheartbeat"
	"github.com/google/uuid"
)

const (
	ServiceNausfAuth     string = string(models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH)
	ServiceNudmUeau      string = string(models.Nrf_NFMgmt_ServiceName_NUDM_UEAU)
	ServiceNudrDR        string = string(models.Nrf_NFMgmt_ServiceName_NUDR_DR)
	ServiceNudmSubManage string = string(models.Nrf_NFMgmt_ServiceName_NUDM_SDM)
)

const (
	ScpDefaultTLSKeyLogPath  = "./log/scpsslkey.log"
	ScpDefaultCertPemPath    = "./cert/scp.pem"
	ScpDefaultPrivateKeyPath = "./cert/scp.key"
	ScpDefaultConfigPath     = "./config/scpcfg.yaml"
	ScpExpectedConfigVersion = "1.0.1"
	ScpSbiDefaultIPv4        = "127.0.0.113"
	ScpSbiDefaultPort        = 8000
	ScpSbiDefaultScheme      = "https"
	ScpDefaultNrfUri         = "https://127.0.0.10:8000"
	NausfAuthUriPrefix       = "/" + ServiceNausfAuth + "/v1"
	NudmUeauUriPrefix        = "/" + ServiceNudmUeau + "/v1"
	NudmSubManageUriPrefix   = "/" + ServiceNudmSubManage + "/v2"
	NudrDRUriPrefix          = "/" + ServiceNudrDR + "/v2"
)

type serviceAPIVersion struct {
	uri  string
	full string
}

var serviceAPIVersions = map[string]serviceAPIVersion{
	ServiceNausfAuth:     {uri: "v1", full: "1.2.3"},
	ServiceNudmUeau:      {uri: "v1", full: "1.2.2"},
	ServiceNudmSubManage: {uri: "v2", full: "2.2.5"},
	ServiceNudrDR:        {uri: "v2", full: "2.2.5"},
}

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if info := c.Info; info != nil {
		if !govalidator.IsIn(info.Version, ScpExpectedConfigVersion) {
			err := errors.New("Config version should be " + ScpExpectedConfigVersion)
			return false, appendInvalid(err)
		}
	}

	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"type(string)"`
	Description string `yaml:"description,omitempty" valid:"type(string)"`
}

type Configuration struct {
	ReadIdleTimeout *time.Duration `yaml:"readIdleTimeout,omitempty" valid:"optional"`
	PingTimeout     *time.Duration `yaml:"pingTimeout,omitempty" valid:"optional"`
	IdleTimeout     *time.Duration `yaml:"idleTimeout,omitempty" valid:"optional"`
	Sbi             *Sbi           `yaml:"sbi,omitempty" valid:"required"`
	NrfUri          string         `yaml:"nrfUri,omitempty" valid:"required"`
	NrfCertPem      string         `yaml:"nrfCertPem,omitempty" valid:"optional"`
	// TS 29.500 §6.10.11.2.1: delegated discovery may require SCP to obtain a token for the original consumer.
	// Disabled by default; enable only when SCP is officially enabled in the deployment.
	DelegatedOAuth bool      `yaml:"delegatedOAuth,omitempty" valid:"type(bool)"`
	ServiceList    []Service `yaml:"serviceList,omitempty" valid:"required"`
	AmfUri         string    `yaml:"amfUri,omitempty" valid:"required"`
	AusfUri        string    `yaml:"ausfUri,omitempty" valid:"required"`
	ChfUri         string    `yaml:"chfUri,omitempty" valid:"required"`
	NefUri         string    `yaml:"nefUri,omitempty" valid:"required"`
	NssfUri        string    `yaml:"nssfUri,omitempty" valid:"required"`
	PcfUri         string    `yaml:"pcfUri,omitempty" valid:"required"`
	SmfUri         string    `yaml:"smfUri,omitempty" valid:"required"`
	UdmUri         string    `yaml:"udmUri,omitempty" valid:"required"`
	UdrUri         string    `yaml:"udrUri,omitempty" valid:"required"`
	UpfUri         string    `yaml:"upfUri,omitempty" valid:"required"`
	// NfHeartBeatTimer is the fallback heartbeat interval in seconds, from 1 to
	// 3600 as the NRF accepts. The interval the NRF assigns always wins.
	NfHeartBeatTimer int32 `yaml:"nfHeartBeatTimer,omitempty" valid:"optional,range(1|3600)"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

func (c *Configuration) validate() (bool, error) {
	if sbi := c.Sbi; sbi != nil {
		if result, err := sbi.validate(); err != nil {
			return result, err
		}
	}
	for i, s := range c.ServiceList {
		if s.ProducerNFInstanceID != "" {
			id, err := uuid.Parse(s.ProducerNFInstanceID)
			if err != nil || id.Version() != 4 {
				return false, appendInvalid(fmt.Errorf("serviceList[%d].producerNfInstanceId must be a UUID v4", i))
			}
		}
		switch s.ServiceName {
		case ServiceNausfAuth, ServiceNudmUeau, ServiceNudmSubManage, ServiceNudrDR:
		default:
			err := errors.New("invalid serviceList[" + strconv.Itoa(i) + "]: " +
				s.ServiceName + ", unsupported service")
			return false, appendInvalid(err)
		}
	}
	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Sbi struct {
	Scheme       string `yaml:"scheme" valid:"scheme,required"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty" valid:"host,required"` // IP that is registered at NRF.
	// IPv6Addr  string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty" valid:"host,required"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty" valid:"port,optional"`
	Tls         *Tls   `yaml:"tls,omitempty" valid:"optional"`
}

func (s *Sbi) validate() (bool, error) {
	govalidator.TagMap["scheme"] = govalidator.Validator(func(str string) bool {
		return str == "https" || str == "http"
	})

	if tls := s.Tls; tls != nil {
		if result, err := tls.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(s)
	return result, appendInvalid(err)
}

type Service struct {
	ServiceName string `yaml:"serviceName"`
	SuppFeat    string `yaml:"suppFeat,omitempty"`
	// Trusted identity of the configured backend, needed to accept instance-specific access tokens.
	ProducerNFInstanceID string `yaml:"producerNfInstanceId,omitempty"`
}

type Tls struct {
	Verify bool   `yaml:"verify,omitempty" valid:"type(bool)"`
	Pem    string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key    string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

func (t *Tls) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(t)
	return result, err
}

func appendInvalid(err error) error {
	var errs govalidator.Errors
	if err == nil {
		return nil
	}
	es, ok := err.(govalidator.Errors)
	if ok {
		for _, e := range es.Errors() {
			errs = append(errs, fmt.Errorf("invalid %w", e))
		}
	} else {
		errs = append(errs, err)
	}
	return error(errs)
}

func (c *Config) Print() {
	c.RLock()
	defer c.RUnlock()

	spew.Config.Indent = "\t"
	str := spew.Sdump(c.Configuration)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}

func (c *Config) Version() string {
	c.RLock()
	defer c.RUnlock()

	if c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level: level,
		}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level:        "info",
			ReportCaller: reportCaller,
		}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}

func (c *Config) SbiScheme() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.Sbi.Scheme != "" {
		return c.Configuration.Sbi.Scheme
	}
	return ScpSbiDefaultScheme
}

func (c *Config) SbiPort() int {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.Sbi.Port != 0 {
		return c.Configuration.Sbi.Port
	}
	return ScpSbiDefaultPort
}

func (c *Config) SbiBindingIP() string {
	c.RLock()
	defer c.RUnlock()

	bindIP := "0.0.0.0"
	if c.Configuration.Sbi.BindingIPv4 != "" {
		if bindIP = os.Getenv(c.Configuration.Sbi.BindingIPv4); bindIP != "" {
			logger.CfgLog.Infof("Parsing ServerIPv4 [%s] from ENV Variable", bindIP)
		} else {
			bindIP = c.Configuration.Sbi.BindingIPv4
		}
	}
	return bindIP
}

func (c *Config) SbiBindingAddr() string {
	return c.SbiBindingIP() + ":" + strconv.Itoa(c.SbiPort())
}

func (c *Config) SbiRegisterIP() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.Sbi.RegisterIPv4 != "" {
		return c.Configuration.Sbi.RegisterIPv4
	}
	return ScpSbiDefaultIPv4
}

func (c *Config) SbiRegisterAddr() string {
	return c.SbiRegisterIP() + ":" + strconv.Itoa(c.SbiPort())
}

func (c *Config) SbiUri() string {
	return c.SbiScheme() + "://" + c.SbiRegisterAddr()
}

func (c *Config) NrfUri() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.NrfUri != "" {
		return c.Configuration.NrfUri
	}
	return ScpDefaultNrfUri
}

func (c *Config) NrfCertPem() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.NrfCertPem != "" {
		return c.Configuration.NrfCertPem
	}
	return "" // havn't setup in config
}

func (c *Config) ServiceList() []Service {
	c.RLock()
	defer c.RUnlock()

	if len(c.Configuration.ServiceList) > 0 {
		return c.Configuration.ServiceList
	}
	return nil
}

func (c *Config) GetCertPemPath() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.Sbi.Tls != nil {
		return c.Configuration.Sbi.Tls.Pem
	}
	return ScpDefaultCertPemPath
}

func (c *Config) GetCertKeyPath() string {
	c.RLock()
	defer c.RUnlock()

	if c.Configuration.Sbi.Tls != nil {
		return c.Configuration.Sbi.Tls.Key
	}
	return ScpDefaultPrivateKeyPath
}

func (c *Config) TLSPemPath() string {
	return c.GetCertPemPath()
}

func (c *Config) TLSKeyPath() string {
	return c.GetCertKeyPath()
}

func (c *Config) NFServices() []models.Nrf_NFMgmt_NFService {
	nfServices := []models.Nrf_NFMgmt_NFService{}
	for i, s := range c.ServiceList() {
		apiVersion, ok := serviceAPIVersions[s.ServiceName]
		if !ok {
			continue
		}
		nfService := models.Nrf_NFMgmt_NFService{
			ServiceInstanceId: strconv.Itoa(i),
			ServiceName:       models.Nrf_NFMgmt_ServiceName(s.ServiceName),
			Versions: []models.Nrf_NFMgmt_NFServiceVersion{
				{
					ApiFullVersion:  apiVersion.full,
					ApiVersionInUri: apiVersion.uri,
				},
			},
			Scheme:          models.UriScheme(c.SbiScheme()),
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			ApiPrefix:       c.SbiUri(),
			IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
				{
					Ipv4Address: c.SbiRegisterIP(),
					Transport:   models.Nrf_NFMgmt_TransportProtocol_TCP,
					Port:        int32(c.SbiPort()),
				},
			},
			SupportedFeatures: s.SuppFeat,
		}
		nfServices = append(nfServices, nfService)
	}
	return nfServices
}

// GetIdleTimeout returns the HTTP server idle timeout. Omitted values preserve
// the previous 1ms timeout; an explicit zero disables the timeout.
func (c *Config) GetIdleTimeout() time.Duration {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration == nil || c.Configuration.IdleTimeout == nil {
		return time.Millisecond
	}
	return *c.Configuration.IdleTimeout
}

// GetReadIdleTimeout returns the HTTP/2 client health-check timeout.
func (c *Config) GetReadIdleTimeout() time.Duration {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration == nil || c.Configuration.ReadIdleTimeout == nil {
		return time.Second
	}
	return *c.Configuration.ReadIdleTimeout
}

// GetPingTimeout returns the HTTP/2 client health-check timeout.
func (c *Config) GetPingTimeout() time.Duration {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration == nil || c.Configuration.PingTimeout == nil {
		return 2 * time.Second
	}
	return *c.Configuration.PingTimeout
}

// GetTLSVerify controls outgoing SBI server certificate verification.
// Configuration is read before traffic starts; omitted verify retains false.
func (c *Config) GetTLSVerify() bool {
	if c == nil {
		return false
	}
	c.RLock()
	defer c.RUnlock()
	return c.Configuration != nil && c.Configuration.Sbi != nil &&
		c.Configuration.Sbi.Tls != nil && c.Configuration.Sbi.Tls.Verify
}

// GetNfHeartBeatTimer returns the fallback heartbeat interval in seconds.
func (c *Config) GetNfHeartBeatTimer() int32 {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration == nil || c.Configuration.NfHeartBeatTimer <= 0 {
		return nfheartbeat.DefaultTimer
	}
	return c.Configuration.NfHeartBeatTimer
}
