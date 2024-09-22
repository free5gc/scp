package processor

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) GetAuthSubsData(
	ueId string,
) *HandlerResponse {
	logger.DetectorLog.Infof("Forward UDM QueryAuthSubsData")

	// TODO: Send request to correct NF by setting correct uri
	targetNfUri := "http://udr.free5gc.org:8000"

	response, problemDetails, err := p.Consumer().SendAuthSubsDataGet(targetNfUri, ueId)

	// NOTE: The response from UDR is guaranteed to be correct
	CurrentAuthProcedure.AuthSubsData = *response

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
