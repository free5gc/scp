package processor

import (
	"context"
	"net/http"

	"github.com/free5gc/openapi/models"
	udmSDM "github.com/free5gc/openapi/udm/SDM"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) GetAuthSubsData(
	ctx context.Context, ueID string, supportedFeatures *string,
) *HandlerResponse {
	logger.DetectorLog.Infof("Forward UDM QueryAuthSubsData")
	rsp, err := p.Consumer().SendAuthSubsDataGet(ctx, p.Context().UdrUri, ueID, supportedFeatures)
	if err != nil {
		return responseFromError(err)
	}
	return response(http.StatusOK, rsp)
}

func (p *Processor) ModifyAuthentication(
	ctx context.Context,
	ueID string,
	patches []models.PatchItem,
	supportedFeatures *string,
) *HandlerResponse {
	logger.DetectorLog.Infof("Forward UDM ModifyAuthentication")
	if err := p.Consumer().ModifyAuthenticationPatch(
		ctx, p.Context().UdrUri, ueID, patches, supportedFeatures,
	); err != nil {
		return responseFromError(err)
	}
	return &HandlerResponse{Status: http.StatusNoContent}
}

func (p *Processor) GetNSSAI(
	ctx context.Context,
	request *udmSDM.GetNSSAIRequest,
) *HandlerResponse {
	rsp, err := p.Consumer().SendGetNSSAIRequest(ctx, p.Context().UdmUri, request)
	if err != nil {
		return responseFromError(err)
	}
	headers := make(map[string][]string)
	if rsp.Cache_Control != "" {
		headers["Cache-Control"] = []string{rsp.Cache_Control}
	}
	if rsp.ETag != "" {
		headers["ETag"] = []string{rsp.ETag}
	}
	if rsp.Last_Modified != "" {
		headers["Last-Modified"] = []string{rsp.Last_Modified}
	}
	if rsp.Udm_SDM_Nssai == nil {
		return &HandlerResponse{Status: http.StatusNotModified, Headers: headers}
	}
	return &HandlerResponse{
		Status: http.StatusOK, Headers: headers, ContentType: "application/json", Body: rsp.Udm_SDM_Nssai,
	}
}
