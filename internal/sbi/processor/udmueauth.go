package processor

import (
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nudr_DataRepository "github.com/free5gc/openapi/udr/DataRepository"
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

	udmReq := models.UdmUeauAuthenticationInfoRequest{
		SupportedFeatures:     authInfo.SupportedFeatures,
		ServingNetworkName:    authInfo.ServingNetworkName,
		ResynchronizationInfo: authInfo.ResynchronizationInfo,
		AusfInstanceId:        authInfo.AusfInstanceId,
		CellCagInfo:           authInfo.CellCagInfo,
		N5gcInd:               authInfo.N5gcInd,
	}

	response, problemDetails, err := p.Consumer().SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &udmReq)

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
	req := &Nudr_DataRepository.CreateAuthenticationStatusRequest{
		UeId:      &supi,
		AuthEvent: &authEvent,
	}

	client, err := p.Consumer().CreateSCPClientToUDR(supi)
	if err != nil {
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	resp, err := client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(ctx, req)
	if err != nil {
		status := int32(http.StatusInternalServerError)
		cause := err.Error()
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if pd, ok := apiErr.Model().(models.ProblemDetails); ok {
				status = pd.Status
				cause = pd.Cause
			}
		}

		problemDetails := &models.ProblemDetails{
			Status: status,
			Cause:  cause,
			Detail: err.Error(),
		}

		logger.DetectorLog.Errorln("ConfirmAuth err:", err.Error())
		gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	_ = resp
	// No response body to close
	gc.Status(http.StatusCreated)
}
