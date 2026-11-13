package sbi

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/internal/sbi/processor"
	util_oauth "github.com/free5gc/scp/internal/util"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	CorsConfigMaxAge = 86400
)

type Endpoint struct {
	Method  string
	Pattern string
	APIFunc gin.HandlerFunc
}

func applyEndpoints(group *gin.RouterGroup, endpoints []Endpoint) {
	for _, endpoint := range endpoints {
		switch endpoint.Method {
		case "GET":
			group.GET(endpoint.Pattern, endpoint.APIFunc)
		case "POST":
			group.POST(endpoint.Pattern, endpoint.APIFunc)
		case "PUT":
			group.PUT(endpoint.Pattern, endpoint.APIFunc)
		case "PATCH":
			group.PATCH(endpoint.Pattern, endpoint.APIFunc)
		case "DELETE":
			group.DELETE(endpoint.Pattern, endpoint.APIFunc)
		}
	}
}

type scp interface {
	Context() *scp_context.ScpContext
	Config() *factory.Config
	Processor() *processor.Processor
}

type Server struct {
	scp

	forwardingClient *http.Client
	httpServer       *http.Server
	router           *gin.Engine
}

func NewServer(scp scp, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		scp: scp,
	}

	s.forwardingClient = &http.Client{CheckRedirect: openapi.RejectRedirects, Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !s.Config().GetTLSVerify()}, // #nosec G402 -- NF configuration
	}}

	s.router = logger_util.NewGinWithLogrus(logger.GinLog)
	s.router.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
			"If-None-Match", "If-Modified-Since",
		},
		ExposeHeaders:   []string{"Content-Length", "ETag", "Last-Modified", "Cache-Control"},
		AllowAllOrigins: true,
		MaxAge:          CorsConfigMaxAge,
	}))
	s.router.Use(s.forwardCallbackRequest)

	for _, api := range []struct {
		serviceName models.Nrf_NFMgmt_ServiceName
		prefix      string
		endpoints   []Endpoint
	}{
		{models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH, factory.NausfAuthUriPrefix, s.getAusfUeAuthEndpoints()},
		{models.Nrf_NFMgmt_ServiceName_NUDM_UEAU, factory.NudmUeauUriPrefix, s.getUdmUeAuthEndpoints()},
		{models.Nrf_NFMgmt_ServiceName_NUDR_DR, factory.NudrDRUriPrefix, s.getUdrAuthSubsDataEndpoints()},
		{models.Nrf_NFMgmt_ServiceName_NUDM_SDM, factory.NudmSubManageUriPrefix, s.getUdmSubManageEndpoints()},
	} {
		group := s.router.Group(api.prefix)
		routerAuthorizationCheck := util_oauth.NewRouterAuthorizationCheck(
			api.serviceName, s.Config().SbiUri()+api.prefix)
		group.Use(s.prepareProxyAuthorization(api.serviceName))
		group.Use(func(c *gin.Context) {
			routerAuthorizationCheck.Check(c, s.Context())
		})
		group.Use(s.forwardAuthorizedProxyRequest)
		applyEndpoints(group, api.endpoints)
	}

	// For not found API
	s.router.NoRoute(s.NonSupportAPI)

	bindAddr := s.Config().SbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(
		bindAddr, tlsKeyLogPath, s.router, s.Config().GetIdleTimeout(),
	); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %+v", err)
		return nil, err
	}

	return s, nil
}

func (s *Server) Run(wg *sync.WaitGroup) error {
	wg.Add(1)
	go s.startServer(wg)
	return nil
}

func (s *Server) Stop() {
	if s.httpServer != nil {
		logger.SBILog.Infof("Stop SBI server (listen on %s)", s.httpServer.Addr)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			logger.SBILog.Errorf("Graceful shutdown failed: %#v", err)
			if closeErr := s.httpServer.Close(); closeErr != nil {
				logger.SBILog.Errorf("Could not close SBI server: %#v", closeErr)
			}
		}
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		wg.Done()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	scheme := s.Config().SbiScheme()
	switch scheme {
	case "http":
		err = s.httpServer.ListenAndServe()
	case "https":
		// TODO: use config file to config path
		err = s.httpServer.ListenAndServeTLS(s.Config().TLSPemPath(), s.Config().TLSKeyPath())
	default:
		err = fmt.Errorf("no support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %+v", err)
	}
	logger.SBILog.Warnf("SBI server (listen on %s) stopped", s.httpServer.Addr)
}

func checkContentTypeIsJSON(gc *gin.Context) (string, error) {
	contentType := gc.GetHeader("Content-Type")
	if mediatype.KindOfMediaType(contentType) != mediatype.MediaKindJSON {
		err := fmt.Errorf("unsupported content type %q", contentType)
		logger.SBILog.Error(err)
		sendProblem(gc, http.StatusUnsupportedMediaType, &models.ProblemDetails{
			Status: http.StatusUnsupportedMediaType, Cause: "UNSUPPORTED_MEDIA_TYPE", Detail: err.Error(),
		})
		return "", err
	}

	return contentType, nil
}

func (s *Server) deserializeData(gc *gin.Context, data interface{}, contentType string) error {
	reqBody, err := gc.GetRawData()
	if err != nil {
		logger.SBILog.Errorf("Get Request Body error: %+v", err)
		sendProblem(gc, http.StatusInternalServerError, openapi.ProblemDetailsSystemFailure(err.Error()))
		return err
	}

	err = openapi.Deserialize(data, reqBody, contentType)
	if err != nil {
		logger.SBILog.Errorf("Deserialize Request Body error: %+v", err)
		sendProblem(gc, http.StatusBadRequest, openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return err
	}

	return nil
}

func (s *Server) buildAndSendHttpResponse(gc *gin.Context, hdlRsp *processor.HandlerResponse) {
	if hdlRsp == nil || hdlRsp.Status == 0 {
		// No Response to send
		return
	}
	rsp := httpwrapper.NewResponse(hdlRsp.Status, hdlRsp.Headers, hdlRsp.Body)
	buildHttpResponseHeader(gc, rsp)
	if rsp.Status == http.StatusNoContent || rsp.Status == http.StatusNotModified || rsp.Body == nil {
		gc.Status(rsp.Status)
		gc.Writer.WriteHeaderNow()
		return
	}
	contentType := hdlRsp.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	if rawBody, ok := rsp.Body.([]byte); ok {
		gc.Data(rsp.Status, contentType, rawBody)
		return
	}
	serializedContentType, rspBody, err := openapi.Serialize(rsp.Body, contentType)

	if err != nil {
		logger.SBILog.Errorln(err)
		sendProblem(gc, http.StatusInternalServerError, openapi.ProblemDetailsSystemFailure(err.Error()))
	} else {
		gc.Data(rsp.Status, serializedContentType, rspBody)
	}
}

func sendProblem(gc *gin.Context, status int, problem *models.ProblemDetails) {
	contentType, body, err := openapi.Serialize(problem, "application/problem+json")
	if err != nil {
		gc.Status(http.StatusInternalServerError)
		return
	}
	gc.Data(status, contentType, body)
}

func buildHttpResponseHeader(gc *gin.Context, rsp *httpwrapper.Response) {
	for k, v := range rsp.Header {
		// Concatenate all values of the Header with ','
		allValues := ""
		for i, vv := range v {
			if i == 0 {
				allValues += vv
			} else {
				allValues += "," + vv
			}
		}
		gc.Header(k, allValues)
	}
}

func (s *Server) NonSupportAPI(gc *gin.Context) {
	uriPath := gc.Request.URL.Path
	logger.DetectorLog.Infoln("Handle not support API: ", uriPath)
	if isPathAtOrBelow(uriPath, "/nudm-sdm/v1") || isPathAtOrBelow(uriPath, "/nudr-dr/v1") {
		gc.Status(http.StatusNotFound)
		return
	}
	s.forwardProxyRequest(gc)
}

func (s *Server) forwardProxyRequest(gc *gin.Context) {
	uriPath := gc.Request.URL.Path

	targetUri := ""
	targetNF, err := extractNFName(uriPath)
	if err != nil {
		logger.DetectorLog.Errorf("Non support API format: %s\n", uriPath)
		gc.Status(http.StatusNotFound)
		return
	}
	targetUri = s.Context().URIForNF(strings.ToUpper(targetNF))
	if targetUri == "" {
		logger.DetectorLog.Errorf("Non support API format: %s\n", uriPath)
		gc.Status(http.StatusNotFound)
		return
	}

	logger.DetectorLog.Infof("Forward the packet to %s: %s", targetNF, targetUri)

	targetURL := fmt.Sprintf("%s%s", targetUri, gc.Request.URL.RequestURI())

	// Forwarding request
	forwardReq, err := http.NewRequestWithContext(gc.Request.Context(), gc.Request.Method, targetURL, gc.Request.Body)
	if err != nil {
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create forward request"})
		return
	}

	// Copy header
	for key, values := range gc.Request.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

	// Send forwarding request
	forwardResp, err := s.forwardingClient.Do(forwardReq)
	if err != nil {
		gc.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
	}
	defer func() {
		if closeErr := forwardResp.Body.Close(); closeErr != nil {
			logger.DetectorLog.Warnln("Failed to close response body:", closeErr)
		}
	}()

	// Response status code, header, and body to client
	for key, values := range forwardResp.Header {
		for _, value := range values {
			gc.Writer.Header().Add(key, value)
		}
	}
	gc.Status(forwardResp.StatusCode)
	_, err = io.Copy(gc.Writer, forwardResp.Body)
	if err != nil {
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write response"})
	}
}

func isPathAtOrBelow(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func extractNFName(uri string) (string, error) {
	re := regexp.MustCompile(`^/n([a-z]+)`)
	matches := re.FindStringSubmatch(uri)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("no NF name found in URI: %s", uri)
}

const (
	callbackHeader     = "3gpp-Sbi-Callback"
	consumerIDHeader   = "3gpp-Sbi-Discovery-requester-nf-instance"
	consumerTypeHeader = "3gpp-Sbi-Discovery-requester-nf-type"
	accessScopeHeader  = "3gpp-Sbi-Access-Scope"
	ccaHeader          = "3gpp-Sbi-Client-Credentials"
)

// TS 29.500 §6.10.7: callback requests bypass access-token acquisition and validation.
func (s *Server) forwardCallbackRequest(gc *gin.Context) {
	if !s.Context().OAuth2Required() || gc.GetHeader(callbackHeader) == "" {
		return
	}
	if gc.Request.Method != http.MethodPost {
		sendProblem(gc, http.StatusBadRequest, openapi.ProblemDetailsMalformedReqSyntax("callback must use POST"))
		gc.Abort()
		return
	}
	s.forwardProxyRequest(gc)
	gc.Abort()
}

// Prepare a producer-bound token before the common router authorization check runs.
func (s *Server) prepareProxyAuthorization(service models.Nrf_NFMgmt_ServiceName) gin.HandlerFunc {
	return func(gc *gin.Context) {
		if !s.Context().OAuth2Required() {
			return
		}
		if _, err := s.Context().ProducerAudience(service); err != nil {
			sendProblem(gc, http.StatusNotFound, openapi.ProblemDetailsMalformedReqSyntax("service is not configured"))
			gc.Abort()
			return
		}
		if len(gc.Request.Header.Values("Authorization")) > 1 {
			sendProblem(gc, http.StatusBadRequest, openapi.ProblemDetailsMalformedReqSyntax("multiple Authorization headers"))
			gc.Abort()
			return
		}
		if gc.GetHeader("Authorization") == "" && !s.acquireDelegatedToken(gc, service) {
			gc.Abort()
		}
	}
}

func (s *Server) forwardAuthorizedProxyRequest(gc *gin.Context) {
	if !s.Context().OAuth2Required() {
		return
	}
	// The router authorization check has already verified this exact token.
	subject, err := scp_context.TokenSubject(gc.GetHeader("Authorization"))
	if err != nil || (gc.GetHeader(consumerIDHeader) != "" && gc.GetHeader(consumerIDHeader) != subject) {
		gc.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		sendProblem(gc, http.StatusUnauthorized, &models.ProblemDetails{
			Status: http.StatusUnauthorized, Cause: "ACCESS_TOKEN_DENIED",
		})
		gc.Abort()
		return
	}
	// Keep the original request and consumer token; do not acquire a token as SCP.
	s.forwardProxyRequest(gc)
	gc.Abort()
}

func (s *Server) acquireDelegatedToken(gc *gin.Context, service models.Nrf_NFMgmt_ServiceName) bool {
	var invalid []models.InvalidParam
	for _, name := range []string{consumerIDHeader, consumerTypeHeader, accessScopeHeader} {
		if strings.TrimSpace(gc.GetHeader(name)) == "" {
			invalid = append(invalid, models.InvalidParam{Param: name})
		}
	}
	if len(invalid) != 0 {
		// TS 29.500 §6.10.11.2.2: missing information is a 400, not an OAuth challenge.
		s.proxyProblem(gc, &models.ProblemDetails{
			Status: http.StatusBadRequest, Cause: "MISSING_ACCESS_TOKEN_INFO", InvalidParams: invalid,
		})
		return false
	}
	consumerID := gc.GetHeader(consumerIDHeader)
	id, err := uuid.Parse(consumerID)
	consumerType := models.Nrf_NFMgmt_NFType(gc.GetHeader(consumerTypeHeader))
	allowed, _ := scp_context.AllowedNfTypesForService(service)
	if err != nil || id.Version() != 4 || !slices.Contains(allowed, consumerType) ||
		!slices.Contains(strings.Fields(gc.GetHeader(accessScopeHeader)), string(service)) {
		s.proxyProblem(gc, &models.ProblemDetails{Status: http.StatusBadRequest, Cause: "MANDATORY_IE_INCORRECT"})
		return false
	}
	// An arbitrary discovery header is not authenticated identity. NRF verifies a forwarded CCA;
	// without one, only a verified TLS peer bound to this consumer ID may request delegation.
	if gc.GetHeader(ccaHeader) == "" && !verifiedConsumer(gc.Request, consumerID) {
		s.proxyProblem(gc, &models.ProblemDetails{Status: http.StatusForbidden, Cause: "ACCESS_TOKEN_DENIED"})
		return false
	}
	tokenCtx, pd, err := s.Context().GetDelegatedTokenCtx(gc.Request.Context(), scp_context.DelegatedTokenRequest{
		ConsumerNFInstanceID: consumerID, ConsumerNFType: consumerType, ServiceName: service,
		Scope: gc.GetHeader(accessScopeHeader), ClientCredentialsAssertion: gc.GetHeader(ccaHeader),
	})
	if err != nil {
		if pd == nil {
			pd = &models.ProblemDetails{Status: http.StatusBadGateway, Cause: "SYSTEM_FAILURE"}
		}
		s.proxyProblem(gc, pd)
		return false
	}
	source, ok := tokenCtx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
	if !ok {
		s.proxyProblem(gc, &models.ProblemDetails{Status: http.StatusBadGateway, Cause: "SYSTEM_FAILURE"})
		return false
	}
	token, err := source.Token()
	if err != nil {
		s.proxyProblem(gc, &models.ProblemDetails{Status: http.StatusBadGateway, Cause: "SYSTEM_FAILURE"})
		return false
	}
	token.SetAuthHeader(gc.Request)
	return true
}

func verifiedConsumer(request *http.Request, consumerID string) bool {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := request.TLS.VerifiedChains[0][0]
	return len(leaf.URIs) == 1 && leaf.URIs[0].String() == "urn:uuid:"+consumerID
}

func (s *Server) proxyProblem(gc *gin.Context, problem *models.ProblemDetails) {
	// TS 29.500 §6.10.11.2.2 / §6.10.8.2: identify SCP as the originator of the error.
	gc.Header("Server", "SCP-"+s.Config().SbiRegisterIP())
	sendProblem(gc, int(problem.Status), problem)
}
