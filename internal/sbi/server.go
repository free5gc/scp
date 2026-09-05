package sbi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/internal/sbi/processor"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
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

	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(scp scp, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		scp: scp,
	}

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

	endpoints := s.getAusfUeAuthEndpoints()
	group := s.router.Group(factory.NausfAuthUriPrefix)
	applyEndpoints(group, endpoints)

	endpoints = s.getUdmUeAuthEndpoints()
	group = s.router.Group(factory.NudmUeauUriPrefix)
	applyEndpoints(group, endpoints)

	endpoints = s.getUdrAuthSubsDataEndpoints()
	group = s.router.Group(factory.NudrDRUriPrefix)
	applyEndpoints(group, endpoints)

	endpoints = s.getUdmSubManageEndpoints()
	group = s.router.Group(factory.NudmSubManageUriPrefix)
	applyEndpoints(group, endpoints)

	// For not found API
	s.router.NoRoute(s.NonSupportAPI)

	bindAddr := s.Config().SbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router); err != nil {
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
	client := &http.Client{CheckRedirect: openapi.RejectRedirects}
	forwardResp, err := client.Do(forwardReq)
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
