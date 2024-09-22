package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) getUdrAuthSubsDataEndpoints() []Endpoint {
	return []Endpoint{

		{
			Method:  http.MethodGet,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-subscription",
			APIFunc: s.apiGetAuthSubsData,
		},
	}
}

func (s *Server) apiGetAuthSubsData(gc *gin.Context) {

	hdlRsp := s.Processor().GetAuthSubsData(gc.Param("ueId"))

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
