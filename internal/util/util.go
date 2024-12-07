package util

import (
	"encoding/json"
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	INVALID_REQUEST       = "Invalid request message framing"
	MALFORMED_REQUEST     = "Malformed request syntax"
	UNAUTHORIZED_CONSUMER = "Unauthorized NF service consumer"
	UNSUPPORTED_RESOURCE  = "Unsupported request resources"
)

func GinProblemJson(c *gin.Context, pd *models.ProblemDetails) {
	c.JSON(int(pd.Status), pd)
	c.Writer.Header().Set("Content-Type", "application/problem+json")
}

func EmptyUeIdProblemJson(c *gin.Context) {
	problemDetail := &models.ProblemDetails{
		Title:  MALFORMED_REQUEST,
		Status: http.StatusBadRequest,
		Detail: "ueId is required",
	}
	GinProblemJson(c, problemDetail)
}

func ToBsonM(data interface{}) bson.M {
	tmp, err := json.Marshal(data)
	if err != nil {
		logger.DetectorLog.Error(err)
	}
	putData := bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		logger.DetectorLog.Error(err)
	}
	return putData
}
