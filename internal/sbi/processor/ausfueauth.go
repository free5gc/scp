package processor

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) PostUeAutentications(
	authInfo models.AuthenticationInfo,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Request")
	scpContext := scp_context.GetSelf()
	ausfUri := scpContext.AusfUri
	targetNfUri := ausfUri

	response, problemDetails, err := p.Consumer().SendUeAuthPostRequest(targetNfUri, authInfo)

	if response != nil {
		return &HandlerResponse{http.StatusCreated, nil, response}
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

func (p *Processor) PutUeAutenticationsConfirmation(
	authCtxId string,
	confirmationData models.ConfirmationData,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Response")
	scpContext := scp_context.GetSelf()
	ausfUri := scpContext.AusfUri
	targetNfUri := ausfUri

	response, problemDetails, err := p.Consumer().SendAuth5gAkaConfirmRequest(targetNfUri, authCtxId, &confirmationData)

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
