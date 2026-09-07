package sbi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/free5gc/openapi"
	udmSDM "github.com/free5gc/openapi/udm/SDM"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdmSubManageEndpoints() []Endpoint {
	return []Endpoint{{
		Method: http.MethodGet, Pattern: "/:supiOrSuci/nssai", APIFunc: s.HandleGetNssai,
	}}
}

func (s *Server) HandleGetNssai(gc *gin.Context) {
	supi := gc.Param("supiOrSuci")
	if supi == "" {
		sendProblem(gc, http.StatusBadRequest, openapi.ProblemDetailsMalformedReqSyntax("missing SUPI"))
		return
	}
	request := &udmSDM.GetNSSAIRequest{Supi: &supi}
	if value, present := gc.GetQuery("plmn-id"); present {
		if value == "" || json.Unmarshal([]byte(value), &request.PlmnId) != nil || request.PlmnId == nil {
			sendProblem(gc, http.StatusBadRequest,
				openapi.ProblemDetailsMalformedReqSyntax("invalid plmn-id query parameter"))
			return
		}
	}
	if value, present := gc.GetQuery("supported-features"); present {
		request.SupportedFeatures = &value
	}
	if value, present := gc.GetQuery("disaster-roaming-ind"); present {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			sendProblem(gc, http.StatusBadRequest,
				openapi.ProblemDetailsMalformedReqSyntax("invalid disaster-roaming-ind query parameter"))
			return
		}
		request.DisasterRoamingInd = &parsed
	}
	if value := gc.GetHeader("If-None-Match"); value != "" {
		request.IfNoneMatch = &value
	}
	if value := gc.GetHeader("If-Modified-Since"); value != "" {
		request.IfModifiedSince = &value
	}

	hdlRsp := s.Processor().GetNSSAI(gc.Request.Context(), request)
	s.buildAndSendHttpResponse(gc, hdlRsp)
}
