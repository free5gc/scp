package sbi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdmSubManageEndpoints() []Endpoint {
	return []Endpoint{
		{
			Method:  http.MethodGet,
			Pattern: "/:supiOrSuci/nssai",
			APIFunc: s.HandleGetNssai,
		},
	}
}

func (s *Server) HandleGetNssai(gc *gin.Context) {
	UdmUri := scp_context.GetSelf().UdmUri
	logger.DetectorLog.Println("Handle Get Nssai Received, but not support detection, forward to UDM: ", UdmUri)
	supi := gc.Param("supiOrSuci")
	// logger.DetectorLog.Println("supi", supi)
	if supi == "" {
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Missing SUPI in the request path"})
		return
	}
	plmnId := gc.Query("plmn-id")
	if plmnId == "" {
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Missing plmn-id in query parameters"})
		return
	}
	decodedPlmnId, err := url.QueryUnescape(plmnId)
	if err != nil {
		logger.DetectorLog.Warnln("Failed to decode plmn-id: ", err)
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plmn-id format"})
		return
	}
	plmnIdStruct := &models.PlmnId{}
	err = json.Unmarshal([]byte(decodedPlmnId), plmnIdStruct)
	if err != nil {
		logger.DetectorLog.Warnln("Failed to parse plmn-id as JSON: ", err)
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plmn-id JSON format"})
		return
	}
	plmnIdJson, err := json.Marshal(plmnIdStruct)
	if err != nil {
		logger.DetectorLog.Warnln("Failed to encode plmn-id back to JSON: ", err)
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error while processing plmn-id"})
		return
	}

	forwardURL := fmt.Sprintf(
		"%s%s/%s/nssai?plmnId=%s",
		UdmUri,
		factory.NudmSubManageUriPrefix,
		supi,
		url.QueryEscape(string(plmnIdJson)),
	)

	req, err := http.NewRequestWithContext(gc.Request.Context(), http.MethodGet, forwardURL, nil)
	if err != nil {
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create forward request"})
		return
	}

	for key, values := range gc.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		gc.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request to UDM"})
		return
	}

	defer func() {
		if err = resp.Body.Close(); err != nil {
			logger.DetectorLog.Warnln("Failed to close response body:", err)
		}
	}()

	gc.Status(resp.StatusCode)
	for key, values := range resp.Header {
		for _, value := range values {
			gc.Writer.Header().Add(key, value)
		}
	}
	_, err = io.Copy(gc.Writer, resp.Body)
	if err != nil {
		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write response"})
	}
}
