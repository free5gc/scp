package sbi

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdmUeAuthEndpoints() []Endpoint {
	return []Endpoint{

		{
			Method:  http.MethodPost,
			Pattern: "/:supiOrSuci/security-information/generate-auth-data",
			APIFunc: s.apiPostGenerateAuthData,
		},
	}
}

func (s *Server) apiPostGenerateAuthData(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var authInfoReq models.AuthenticationInfoRequest
	if err := s.deserializeData(gc, &authInfoReq, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PostGenerateAuthData(gc.Param("supiOrSuci"), authInfoReq)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
