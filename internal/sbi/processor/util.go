package processor

import (
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/util/mongoapi"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	ERR_MANDATORY_ABSENT = "Mandatory type is absent"
	ERR_MISS_CONDITION   = "Miss condition"
	ERR_VALUE_INCORRECT  = "Unexpected value is received"
)

type ConfirmationResourceURI string

const (
	ConfirmationResourceURI_5_G_AKA     ConfirmationResourceURI = "/5g-aka-confirmation"
	ConfirmationResourceURI_EAP_SESSION ConfirmationResourceURI = "/eap-session"
)

// Define every thing you want in this struct,
// so that you can use them in different message handler
type AuthProcedureInfo struct {
	AuthSubsData         models.AuthenticationSubscription
	ServingNetworkName   string // retrieve from AMF
	AuthenticationVector models.AuthenticationVector
}

func (p *Processor) CreateAuthenticationStatusProcedure(c *gin.Context, collName string, ueId string, putData bson.M) {
	filter := bson.M{"ueId": ueId}
	putData["ueId"] = ueId

	if _, err := mongoapi.RestfulAPIPutOne(collName, filter, putData); err != nil {
		logger.DetectorLog.Errorf("CreateAuthenticationStatusProcedure err: %+v", err)
	}

	c.Status(http.StatusNoContent)
}
