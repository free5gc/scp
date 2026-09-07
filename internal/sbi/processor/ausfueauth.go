package processor

import (
	"context"
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) PostUeAutentications(
	ctx context.Context,
	authInfo models.Ausf_UEAU_AuthenticationInfo,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Request")
	rsp, err := p.Consumer().SendUeAuthPostRequest(ctx, p.Context().AusfUri, authInfo)
	if err != nil {
		return responseFromError(err)
	}
	return response(http.StatusCreated, rsp)
}

func (p *Processor) PutUeAutenticationsConfirmation(
	ctx context.Context,
	authCtxID string,
	confirmationData models.Ausf_UEAU_ConfirmationData,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Response")
	rsp, err := p.Consumer().SendAuth5gAkaConfirmRequest(ctx, p.Context().AusfUri, authCtxID, &confirmationData)
	if err != nil {
		return responseFromError(err)
	}
	return response(http.StatusOK, rsp)
}

func (p *Processor) PostEapAuthenticationConfirmation(
	ctx context.Context,
	authCtxID string,
	eapSession models.Ausf_UEAU_EapSession,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF EAP Authentication Response")
	rsp, err := p.Consumer().SendEapAuthConfirmRequest(ctx, p.Context().AusfUri, authCtxID, &eapSession)
	if err != nil {
		return responseFromError(err)
	}
	return response(http.StatusOK, rsp)
}
