package sbi

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
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

	s.router.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		MaxAge:           CorsConfigMaxAge,
	}))

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
		if err := s.httpServer.Close(); err != nil {
			logger.SBILog.Errorf("Could not close SBI server: %#v", err)
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
	if scheme == "http" {
		err = s.httpServer.ListenAndServe()
	} else if scheme == "https" {
		// TODO: use config file to config path
		err = s.httpServer.ListenAndServeTLS(s.Config().TLSPemPath(), s.Config().TLSKeyPath())
	} else {
		err = fmt.Errorf("No support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %+v", err)
	}
	logger.SBILog.Warnf("SBI server (listen on %s) stopped", s.httpServer.Addr)
}

func checkContentTypeIsJSON(gc *gin.Context) (string, error) {
	var err error
	contentType := gc.GetHeader("Content-Type")
	if openapi.KindOfMediaType(contentType) != openapi.MediaKindJSON {
		err = fmt.Errorf("Wrong content type %q", contentType)
	}

	if err != nil {
		logger.SBILog.Error(err)
		gc.JSON(http.StatusInternalServerError,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return "", err
	}

	return contentType, nil
}

func (s *Server) deserializeData(gc *gin.Context, data interface{}, contentType string) error {
	reqBody, err := gc.GetRawData()
	if err != nil {
		logger.SBILog.Errorf("Get Request Body error: %+v", err)
		gc.JSON(http.StatusInternalServerError,
			openapi.ProblemDetailsSystemFailure(err.Error()))
		return err
	}

	err = openapi.Deserialize(data, reqBody, contentType)
	if err != nil {
		logger.SBILog.Errorf("Deserialize Request Body error: %+v", err)
		gc.JSON(http.StatusBadRequest,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return err
	}

	return nil
}

func (s *Server) buildAndSendHttpResponse(gc *gin.Context, hdlRsp *processor.HandlerResponse, multipart bool) {
	if hdlRsp.Status == 0 {
		// No Response to send
		return
	}

	rsp := httpwrapper.NewResponse(hdlRsp.Status, hdlRsp.Headers, hdlRsp.Body)

	buildHttpResponseHeader(gc, rsp)

	var rspBody []byte
	var contentType string
	var err error
	if multipart {
		rspBody, contentType, err = openapi.MultipartSerialize(rsp.Body)
	} else {
		// TODO: support other JSON content-type
		rspBody, err = openapi.Serialize(rsp.Body, "application/json")
		contentType = "application/json"
	}

	if err != nil {
		logger.SBILog.Errorln(err)
		gc.JSON(http.StatusInternalServerError, openapi.ProblemDetailsSystemFailure(err.Error()))
	} else {
		gc.Data(rsp.Status, contentType, rspBody)
	}
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

	targetUri := ""
	targetNF, err := extractNFName(uriPath)
	if err != nil {
		logger.DetectorLog.Errorf("Non support API format: %s\n", uriPath)
		return
	}
	if scp_context.NFtoUriMap[strings.ToUpper(targetNF)] != "" {
		targetUri = scp_context.NFtoUriMap[strings.ToUpper(targetNF)]
	}
	if targetUri == "" {
		logger.DetectorLog.Errorf("Non support API format: %s\n", uriPath)
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
	client := &http.Client{}
	forwardResp, err := client.Do(forwardReq)
	if err != nil {
		gc.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
	}
	defer func() {
		if closeErr := forwardResp.Body.Close(); closeErr != nil {
			logger.DetectorLog.Warnln("Failed to close response body:", err)
		}
	}()

	// Response status code, header, and body to client
	gc.Status(forwardResp.StatusCode)
	for key, values := range forwardResp.Header {
		for _, value := range values {
			gc.Writer.Header().Add(key, value)
		}
	}
	_, err = io.Copy(gc.Writer, forwardResp.Body)
	if err != nil {
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write response"})
	}
}

func extractNFName(uri string) (string, error) {
	re := regexp.MustCompile(`^/n([a-z]+)`)
	matches := re.FindStringSubmatch(uri)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("no NF name found in URI: %s", uri)
}
