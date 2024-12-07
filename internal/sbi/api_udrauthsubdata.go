package sbi

import (
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
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
			Pattern: "/subscription-data/:ueId/:servingPlmnId/provisioned-data/am-data",
			APIFunc: s.HandleCreateAuthenticationStatus,
		},
		// {
		// 	Method:  http.MethodGet,
		// 	Pattern: "/subscription-data/:ueId/:servingPlmnId/provisioned-data/am-data",
		// 	APIFunc: s.HandleQueryAmData,
		// },
		// {
		// 	Method:  "",
		// 	Pattern: "",
		// 	APIFunc: s.NonSupportAPI,
		// },
	}
}

func (s *Server) apiGetAuthSubsData(gc *gin.Context) {

	hdlRsp := s.Processor().GetAuthSubsData(gc.Param("ueId"))

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
func (s *Server) apiPatchAuthSubsData(gc *gin.Context) {
	var patchItemArray []models.PatchItem
	if err := gc.ShouldBindJSON(&patchItemArray); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Invalid patchItem JSON", "details": err.Error()})
		return
	}
	hdlRsp := s.Processor().ModifyAuthentication(gc.Param("ueId"), patchItemArray)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
func (s *Server) HandleCreateAuthenticationStatus(gc *gin.Context) {
	var authEvent models.AuthEvent

	requestBody, err := gc.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.DetectorLog.Errorf("Get Request Body error: %+v", err)
		gc.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&authEvent, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.DetectorLog.Errorln(problemDetail)
		gc.JSON(http.StatusBadRequest, rsp)
		return
	}

	logger.DetectorLog.Tracef("Handle CreateAuthenticationStatus")

	putData := util.ToBsonM(authEvent)
	ueId := gc.Params.ByName("ueId")
	if ueId == "" {
		util.EmptyUeIdProblemJson(gc)
		return
	}
	collName := "subscriptionData.authenticationData.authenticationStatus"

	s.Processor().CreateAuthenticationStatusProcedure(gc, collName, ueId, putData)
}
