package sbi

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) getAusfUeAuthEndpoints() []Endpoint {
	return []Endpoint{

		{
			Method:  http.MethodPost,
			Pattern: "/ue-authentications",
			APIFunc: s.apiPostUeAutentications,
		},
		{
			Method:  http.MethodPut,
			Pattern: "/ue-authentications/:authCtxId/5g-aka-confirmation",
			APIFunc: s.apiPutUeAutenticationsConfirmation,
		},
	}
}

func (s *Server) apiPostUeAutentications(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var authInfo models.AuthenticationInfo
	if err := s.deserializeData(gc, &authInfo, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PostUeAutentications(authInfo)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}

func (s *Server) apiPutUeAutenticationsConfirmation(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var confirmationData models.ConfirmationData
	if err := s.deserializeData(gc, &confirmationData, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PutUeAutenticationsConfirmation(gc.Param("authCtxId"), confirmationData)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
