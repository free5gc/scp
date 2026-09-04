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
		{
			Method:  http.MethodPost,
			Pattern: "/ue-authentications/:authCtxId/eap-session",
			APIFunc: s.apiPostEapAuthenticationConfirmation,
		},
	}
}

func (s *Server) apiPostEapAuthenticationConfirmation(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}
	var eapSession models.Ausf_UEAU_EapSession
	if err := s.deserializeData(gc, &eapSession, contentType); err != nil {
		return
	}
	hdlRsp := s.Processor().PostEapAuthenticationConfirmation(
		gc.Request.Context(), gc.Param("authCtxId"), eapSession)
	s.buildAndSendHttpResponse(gc, hdlRsp)
}

func (s *Server) apiPostUeAutentications(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var authInfo models.Ausf_UEAU_AuthenticationInfo
	if err := s.deserializeData(gc, &authInfo, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PostUeAutentications(gc.Request.Context(), authInfo)

	s.buildAndSendHttpResponse(gc, hdlRsp)
}

func (s *Server) apiPutUeAutenticationsConfirmation(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}

	var confirmationData models.Ausf_UEAU_ConfirmationData
	if err := s.deserializeData(gc, &confirmationData, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PutUeAutenticationsConfirmation(
		gc.Request.Context(), gc.Param("authCtxId"), confirmationData)

	s.buildAndSendHttpResponse(gc, hdlRsp)
}
