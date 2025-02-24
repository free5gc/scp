package processor

import (
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/udr/DataRepository"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/gin-gonic/gin"
)

func (p *Processor) PostGenerateAuthData(
	supiOrSuci string,
	authInfo models.AuthenticationInfoRequest,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward UDM UE Authentication Request")

	scpContext := scp_context.GetSelf()
	udmUri := scpContext.UdmUri
	targetNfUri := udmUri

	response, problemDetails, err := p.Consumer().SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfo)

	if response != nil {
		return &HandlerResponse{http.StatusOK, nil, response}
	} else if problemDetails != nil {
		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.DetectorLog.Errorln("end")
	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}

func (p *Processor) ConfirmAuthDataProcedure(
	gc *gin.Context,
	authEvent models.AuthEvent,
	supi string,
) {
	ctx, pd, err := p.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		gc.JSON(int(pd.Status), pd)
		return
	}
	var createAuthParam DataRepository.CreateAuthenticationStatusRequest
	var optInterface *models.AuthEvent
	createAuthParam.AuthEvent = optInterface
	createAuthParam.UeId = &supi
	client, err := p.Consumer().CreateSCPClientToUDR(supi)
	if err != nil {
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	resp, err := client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(
		ctx, &createAuthParam)
	// TO-DO: The following error check, resp haven't define in r17
	if err != nil {
		// 	problemDetails := &models.ProblemDetails{
		// 		Status: int32(resp.StatusCode),
		// 		Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
		// 		Detail: err.Error(),
		// 	}

		logger.DetectorLog.Errorln("ConfirmAuth err:", err.Error(), "resp: ", resp)
		// 	gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	// defer func() {
	// 	if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
	// 		logger.DetectorLog.Errorf("CreateAuthenticationStatus response body cannot close: %+v", rspCloseErr)
	// 	}
	// }()

	gc.Status(http.StatusCreated)
}
