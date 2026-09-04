package processor

import (
	"context"
	"fmt"
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/util"
	"github.com/free5gc/util/mongoapi"
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

type AuthProcedureInfo struct {
	AuthSubsData         models.Udr_DR_AuthenticationSubscription
	ServingNetworkName   string
	AuthenticationVector models.Udm_UEAU_AuthenticationVector
}

type AuthenticationStatusStore interface {
	Upsert(ctx context.Context, collection, ueID string, data bson.M) error
}

type mongoAuthenticationStatusStore struct{}

func (mongoAuthenticationStatusStore) Upsert(
	_ context.Context,
	collection, ueID string,
	data bson.M,
) error {
	filter := bson.M{"ueId": ueID}
	data["ueId"] = ueID
	_, err := mongoapi.RestfulAPIPutOne(collection, filter, data)
	return err
}

func (p *Processor) CreateAuthenticationStatusProcedure(
	ctx context.Context,
	ueID string,
	authEvent models.Udm_UEAU_AuthEvent,
) *HandlerResponse {
	const collection = "subscriptionData.authenticationData.authenticationStatus"
	data := util.ToBsonM(authEvent)
	if err := p.authenticationStatusStore.Upsert(ctx, collection, ueID, data); err != nil {
		return response(http.StatusInternalServerError, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: fmt.Sprintf("store authentication status: %v", err),
		})
	}
	return &HandlerResponse{Status: http.StatusNoContent}
}
