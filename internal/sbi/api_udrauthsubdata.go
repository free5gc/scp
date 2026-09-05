package sbi

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/util"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdrAuthSubsDataEndpoints() []Endpoint {
	return []Endpoint{
		{
			Method:  http.MethodGet,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-subscription",
			APIFunc: s.apiGetAuthSubsData,
		},
		{
			Method:  http.MethodPatch,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-subscription",
			APIFunc: s.apiPatchAuthSubsData,
		},
		{
			Method:  http.MethodPut,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-status",
			APIFunc: s.HandleCreateAuthenticationStatus,
		},
	}
}

func (s *Server) apiGetAuthSubsData(gc *gin.Context) {
	var supportedFeatures *string
	if value, present := gc.GetQuery("supported-features"); present {
		supportedFeatures = &value
	}
	hdlRsp := s.Processor().GetAuthSubsData(
		gc.Request.Context(), gc.Param("ueId"), supportedFeatures)

	s.buildAndSendHttpResponse(gc, hdlRsp)
}

func (s *Server) apiPatchAuthSubsData(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}
	var patchItemArray []models.PatchItem
	if err := s.deserializeData(gc, &patchItemArray, contentType); err != nil {
		return
	}
	var supportedFeatures *string
	if value, present := gc.GetQuery("supported-features"); present {
		supportedFeatures = &value
	}
	hdlRsp := s.Processor().ModifyAuthentication(
		gc.Request.Context(), gc.Param("ueId"), patchItemArray, supportedFeatures)

	s.buildAndSendHttpResponse(gc, hdlRsp)
}

func (s *Server) HandleCreateAuthenticationStatus(gc *gin.Context) {
	contentType, err := checkContentTypeIsJSON(gc)
	if err != nil {
		return
	}
	var authEvent models.Udm_UEAU_AuthEvent
	if err := s.deserializeData(gc, &authEvent, contentType); err != nil {
		return
	}
	ueID := gc.Param("ueId")
	if ueID == "" {
		util.EmptyUeIdProblemJson(gc)
		return
	}
	hdlRsp := s.Processor().CreateAuthenticationStatusProcedure(gc.Request.Context(), ueID, authEvent)
	s.buildAndSendHttpResponse(gc, hdlRsp)
}
