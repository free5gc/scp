package sbi

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdmUeAuthEndpoints() []Endpoint {
	return []Endpoint{
		{
			Method:  http.MethodPost,
			Pattern: "/:supiOrSuci/security-information/generate-auth-data",
			APIFunc: s.apiPostGenerateAuthData,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/:supiOrSuci/auth-events",
			APIFunc: s.HandleConfirmAuth,
		},
	}
}

func (s *Server) apiPostGenerateAuthData(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var authInfoReq models.Udm_UEAU_AuthenticationInfoRequest
	if err := s.deserializeData(gc, &authInfoReq, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PostGenerateAuthData(
		gc.Request.Context(), gc.Param("supiOrSuci"), authInfoReq)

	s.buildAndSendHttpResponse(gc, hdlRsp)
}

func (s *Server) HandleConfirmAuth(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}
	var authEvent models.Udm_UEAU_AuthEvent
	if err := s.deserializeData(gc, &authEvent, contentType); err != nil {
		return
	}
	logger.DetectorLog.Println("Handle ConfirmAuthDataRequest")
	hdlRsp := s.Processor().ConfirmAuthDataProcedure(
		gc.Request.Context(), authEvent, gc.Param("supiOrSuci"))
	s.buildAndSendHttpResponse(gc, hdlRsp)
}
