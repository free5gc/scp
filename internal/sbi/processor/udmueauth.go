package processor

import (
	"context"
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) PostGenerateAuthData(
	ctx context.Context,
	supiOrSuci string,
	authInfo models.Udm_UEAU_AuthenticationInfoRequest,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward UDM UE Authentication Request")
	rsp, err := p.Consumer().SendGenerateAuthDataRequest(ctx, p.Context().UdmUri, supiOrSuci, &authInfo)
	if err != nil {
		return responseFromError(err)
	}
	return response(http.StatusOK, rsp)
}

func (p *Processor) ConfirmAuthDataProcedure(
	ctx context.Context,
	authEvent models.Udm_UEAU_AuthEvent,
	supi string,
) *HandlerResponse {
	if err := p.Consumer().CreateAuthenticationStatus(ctx, p.Context().UdrUri, supi, &authEvent); err != nil {
		return responseFromError(err)
	}
	return response(http.StatusCreated, struct{}{})
}
