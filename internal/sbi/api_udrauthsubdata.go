package sbi

import (
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/internal/util"
	"github.com/gin-gonic/gin"
)

func (s *Server) getUdrAuthSubsDataEndpoints() []Endpoint {
	return []Endpoint{

		{
			Method:  http.MethodGet,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-subscription",
			APIFunc: s.apiGetAuthSubsData,
		},
		{
			Method:  http.MethodPatch,
			Pattern: "/subscription-data/:ueId/authentication-data/authentication-subscription",
			APIFunc: s.apiPatchAuthSubsData,
		},
		{
			Method:  http.MethodPut,
			Pattern: "/subscription-data/:ueId/:servingPlmnId/provisioned-data/am-data",
			APIFunc: s.HandleCreateAuthenticationStatus,
		},
		// {
		// 	Method:  http.MethodGet,
		// 	Pattern: "/subscription-data/:ueId/:servingPlmnId/provisioned-data/am-data",
		// 	APIFunc: s.HandleQueryAmData,
		// },
		// {
		// 	Method:  "",
		// 	Pattern: "",
		// 	APIFunc: s.NonSupportAPI,
		// },
	}
}

func (s *Server) apiGetAuthSubsData(gc *gin.Context) {

	hdlRsp := s.Processor().GetAuthSubsData(gc.Param("ueId"))

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
func (s *Server) apiPatchAuthSubsData(gc *gin.Context) {
	var patchItemArray []models.PatchItem
	if err := gc.ShouldBindJSON(&patchItemArray); err != nil {
		gc.JSON(http.StatusBadRequest, gin.H{"error": "Invalid patchItem JSON", "details": err.Error()})
		return
	}
	hdlRsp := s.Processor().ModifyAuthentication(gc.Param("ueId"), patchItemArray)

	s.buildAndSendHttpResponse(gc, hdlRsp, false)
}
func (s *Server) HandleCreateAuthenticationStatus(gc *gin.Context) {
	var authEvent models.AuthEvent

	requestBody, err := gc.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.DetectorLog.Errorf("Get Request Body error: %+v", err)
		gc.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&authEvent, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.DetectorLog.Errorln(problemDetail)
		gc.JSON(http.StatusBadRequest, rsp)
		return
	}

	logger.DetectorLog.Tracef("Handle CreateAuthenticationStatus")

	putData := util.ToBsonM(authEvent)
	ueId := gc.Params.ByName("ueId")
	if ueId == "" {
		util.EmptyUeIdProblemJson(gc)
		return
	}
	collName := "subscriptionData.authenticationData.authenticationStatus"

	s.Processor().CreateAuthenticationStatusProcedure(gc, collName, ueId, putData)
}

// func (s *Server) NonSupportAPI(gc *gin.Context) {
// 	// 設定目標服務的 URL
// 	targetServiceBaseURL := scp_context.GetSelf().UdrUri

// 	// 構造目標 URL（原始請求的路徑和查詢參數）
// 	targetURL := fmt.Sprintf("%s%s?%s", targetServiceBaseURL, gc.Request.URL.Path, gc.Request.URL.RawQuery)
// 	logger.DetectorLog.Println("targetURL: ", targetURL)
// 	// 創建轉發請求
// 	forwardReq, err := http.NewRequest(gc.Request.Method, targetURL, gc.Request.Body)
// 	if err != nil {
// 		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create forward request"})
// 		return
// 	}

// 	// 複製原始請求的標頭到轉發請求
// 	for key, values := range gc.Request.Header {
// 		for _, value := range values {
// 			forwardReq.Header.Add(key, value)
// 		}
// 	}

// 	// 發送轉發請求
// 	client := &http.Client{}
// 	forwardResp, err := client.Do(forwardReq)
// 	if err != nil {
// 		gc.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
// 		return
// 	}
// 	defer forwardResp.Body.Close()

// 	// 將回應的狀態碼、標頭和主體內容返回給客戶端
// 	gc.Status(forwardResp.StatusCode)
// 	for key, values := range forwardResp.Header {
// 		for _, value := range values {
// 			gc.Writer.Header().Add(key, value)
// 		}
// 	}
// 	_, err = io.Copy(gc.Writer, forwardResp.Body)
// 	if err != nil {
// 		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write response"})
// 	}
// }

// func (s *Server) HandleQueryAmData(gc *gin.Context) {

// 	UdrUri := scp_context.GetSelf().UdrUri
// 	logger.DetectorLog.Println("Handle Get Query AmData Received, but not support detection, forward to UDR: ", UdrUri)
// 	ueId := gc.Param("ueId")
// 	logger.DetectorLog.Println("ueId", ueId)
// 	servingPlmnId := gc.Param("servingPlmnId")
// 	// if supi == "" {
// 	// 	gc.JSON(http.StatusBadRequest, gin.H{"error": "Missing SUPI in the request path"})
// 	// 	return
// 	// }
// 	forwardURL := fmt.Sprintf("%s%s/subscription-data/%s/%s/provisioned-data/am-data", UdrUri, factory.NudrDRUriPrefix, ueId, servingPlmnId)

// 	req, err := http.NewRequest(http.MethodGet, forwardURL, nil)
// 	if err != nil {
// 		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create forward request"})
// 		return
// 	}

// 	for key, values := range gc.Request.Header {
// 		for _, value := range values {
// 			req.Header.Add(key, value)
// 		}
// 	}

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		gc.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request to UDM"})
// 		return
// 	}
// 	defer resp.Body.Close()

// 	gc.Status(resp.StatusCode)
// 	for key, values := range resp.Header {
// 		for _, value := range values {
// 			gc.Writer.Header().Add(key, value)
// 		}
// 	}
// 	_, err = io.Copy(gc.Writer, resp.Body)
// 	if err != nil {
// 		gc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write response"})
// 	}

// }
