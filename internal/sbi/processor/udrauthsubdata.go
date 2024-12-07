package processor

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) GetAuthSubsData(
	ueId string,
) *HandlerResponse {
	logger.DetectorLog.Infof("Forward UDM QueryAuthSubsData")

	// TODO: Send request to correct NF by setting correct uri
	// targetNfUri := "http://udr.free5gc.org:8000"
	scpContext := scp_context.GetSelf()
	udrUri := scpContext.UdrUri
	targetNfUri := udrUri

	response, problemDetails, err := p.Consumer().SendAuthSubsDataGet(targetNfUri, ueId)

	// NOTE: The response from UDR is guaranteed to be correct
	CurrentAuthProcedure.AuthSubsData = *response
	logger.DetectorLog.Infof("CurrentAuthProcedure.AuthSubsData: ", CurrentAuthProcedure.AuthSubsData)

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

	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}

func (p *Processor) ModifyAuthentication(
	ueId string, patchItemArray []models.PatchItem,
) *HandlerResponse {
	logger.DetectorLog.Infof("Forward UDM ModifyAuthentication")

	scpContext := scp_context.GetSelf()
	udrUri := scpContext.UdrUri
	targetNfUri := udrUri

	problemDetails, err := p.Consumer().ModifyAuthenticationPatch(targetNfUri, ueId, patchItemArray)
	if problemDetails != nil {
		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
	} else if err == nil {
		return &HandlerResponse{http.StatusNoContent, nil, nil}
	}

	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}

	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}
