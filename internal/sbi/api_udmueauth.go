package sbi

import (
	"net/http"

	"github.com/free5gc/openapi"
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

	var authInfoReq models.AuthenticationInfoRequest
	if err := s.deserializeData(gc, &authInfoReq, contentType); err != nil {
		return
	}

	hdlRsp := s.Processor().PostGenerateAuthData(gc.Param("supiOrSuci"), authInfoReq)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}

func (s *Server) HandleConfirmAuth(gc *gin.Context) {
	var authEvent models.AuthEvent
	requestBody, err := gc.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.DetectorLog.Errorln("Get Request Body error: ", err)
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

	supi := gc.Params.ByName("supiOrSuci")
	logger.DetectorLog.Println("Handle ConfirmAuthDataRequest")

	s.Processor().ConfirmAuthDataProcedure(gc, authEvent, supi)
}
