package processor

import (
	"encoding/hex"
	"net/http"

	"github.com/free5gc/UeauCommon"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
)

func (p *Processor) PostUeAutentications(
	authInfo models.AuthenticationInfo,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Request")
	scpContext := scp_context.GetSelf()
	ausfUri := scpContext.AusfUri

	// NOTE: The request from AMF is guaranteed to be correct

	// TODO: Send request to target NF by setting correct uri
	// targetNfUri := "http://ausf.free5gc.org:8000"
	targetNfUri := ausfUri

	servingNetworkName = authInfo.ServingNetworkName
	CurrentAuthProcedure.ServingNetworkName = servingNetworkName

	response, problemDetails, err := p.Consumer().SendUeAuthPostRequest(targetNfUri, &authInfo)

	// TODO: Check IEs in response body is correct

	// TS 29.509 6.1.6.2.3, UEAuthenticationCtx, authType
	// if response.AuthType == "" {
	// 	logger.DetectorLog.Errorln("UeAuthenticationCtx.AuthType:", ERR_MANDATORY_ABSENT)
	// } else if response.AuthType != models.AuthType(CurrentAuthProcedure.AuthSubsData.AuthenticationMethod) {
	// 	logger.DetectorLog.Errorln("UeAuthenticationCtx.AuthType:", ERR_VALUE_INCORRECT)
	// }
	// response.AuthType = models.AuthType(CurrentAuthProcedure.AuthSubsData.AuthenticationMethod)

	// TS 29.509 6.1.3.1, Overview
	// var Nausf_Auth string = targetNfUri + "/nausf-auth/v1/ue-authentications/"
	// resource := Nausf_Auth + CurrentAuthProcedure.supiOrSuci

	// // TS 29.509 6.1.6.3.3
	// if response.AuthType == models.AuthType__5_G_AKA {

	// 	// TS 29.509 6.1.6.2.3, UEAuthenticationCtx, _links
	// 	ResourceName := "5g-aka" // strings.ToLower(models.AuthType__5_G_AKA)
	// 	if len(response.Links) == 0 {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Links:", ERR_MANDATORY_ABSENT)
	// 	} else if _, ok := response.Links[ResourceName]; !ok {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Links:", ERR_VALUE_INCORRECT)
	// 		response.Links = make(map[string]models.LinksValueSchema)
	// 	}

	// 	// TS 29.509 6.1.3.3.2, Resource Definition
	// 	ConfirmationUri := resource + string(ConfirmationResourceURI_5_G_AKA)

	// 	// TS 29.509 6.1.6.2.3, UEAuthenticationCtx, _links
	// 	if response.Links[ResourceName].Href == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.LinksValueSchema.Hert:", ERR_MANDATORY_ABSENT)
	// 	} else if response.Links[ResourceName].Href != ConfirmationUri {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.LinksValueSchema.Hert:", ERR_VALUE_INCORRECT)
	// 	}
	// 	response.Links[ResourceName] = models.LinksValueSchema{
	// 		Href: ConfirmationUri,
	// 	}

	// 	// TS 29.509 6.1.6.2.5, Av5gAka
	// 	var AuthData models.Av5gAka
	// 	mapstructure.Decode(response.Var5gAuthData, &AuthData)
	// 	// AuthData, _ := response.Var5gAuthData.(models.Av5gAka)
	// 	// logger.DetectorLog.Errorln("Rand: ", AuthData.Rand)
	// 	// logger.DetectorLog.Errorln("Autn: ", AuthData.Autn)
	// 	// logger.DetectorLog.Errorln("XresStar: ", AuthData.HxresStar)

	// 	// TS 29.509 6.1.6.2.5, Av5gAka, rand
	// 	if AuthData.Rand == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Rand:", ERR_MANDATORY_ABSENT)
	// 	} else if AuthData.Rand != CurrentAuthProcedure.AuthenticationVector.Rand {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Rand:", ERR_VALUE_INCORRECT)
	// 	}
	// 	AuthData.Rand = CurrentAuthProcedure.AuthenticationVector.Rand

	// 	// TS 29.509 6.1.6.2.5, Av5gAka, autn
	// 	if AuthData.Autn == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Autn:", ERR_MANDATORY_ABSENT)
	// 	} else if AuthData.Autn != CurrentAuthProcedure.AuthenticationVector.Autn {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Autn:", ERR_VALUE_INCORRECT)
	// 	}
	// 	AuthData.Autn = CurrentAuthProcedure.AuthenticationVector.Autn

	// 	// TS 33.501 A.5, HRES* and HXRES* derivation function
	// 	P0, _ := hex.DecodeString(CurrentAuthProcedure.AuthenticationVector.Rand)
	// 	P1, _ := hex.DecodeString(CurrentAuthProcedure.AuthenticationVector.XresStar)
	// 	P0AndP1 := append(P0, P1...)
	// 	HxresStar := hex.EncodeToString(
	// 		retrieveHxresStar(P0AndP1),
	// 	)

	// 	// TS 29.509 6.1.6.2.5, Av5gAka, hxresStar
	// 	if AuthData.HxresStar == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.HxresStar:", ERR_MANDATORY_ABSENT)
	// 	} else if AuthData.HxresStar != HxresStar {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.HxresStar:", ERR_VALUE_INCORRECT)
	// 	}
	// 	AuthData.HxresStar = HxresStar

	// 	response.Var5gAuthData = AuthData

	// } else if response.AuthType == models.AuthType_EAP_AKA_PRIME {

	// 	// TS 29.509 6.1.6.2.7, EapSession, _links
	// 	ResourceName := "eap-session" // strings.ToLower(models.AuthType__5_G_AKA)
	// 	if len(response.Links) == 0 {
	// 		logger.DetectorLog.Errorln("EapSession.Links:", ERR_MISS_CONDITION)
	// 	} else if _, ok := response.Links[ResourceName]; !ok {
	// 		logger.DetectorLog.Errorln("EapSession.Links:", ERR_VALUE_INCORRECT)
	// 		response.Links = make(map[string]models.LinksValueSchema)
	// 	}

	// 	// TS 29.509 6.1.3.3.2, Resource Definition
	// 	ConfirmationUri := resource + string(ConfirmationResourceURI_EAP_SESSION)

	// 	// TS 29.509 6.1.6.2.3, EapSession, _links
	// 	if response.Links[ResourceName].Href == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.LinksValueSchema.Hert:", ERR_MISS_CONDITION)
	// 	} else if response.Links[ResourceName].Href != ConfirmationUri {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.LinksValueSchema.Hert:", ERR_VALUE_INCORRECT)
	// 	}
	// 	response.Links[ResourceName] = models.LinksValueSchema{
	// 		Href: ConfirmationUri,
	// 	}

	// 	// TS 29.509 6.1.6.2.7, EapSession
	// 	var AuthData models.EapSession
	// 	mapstructure.Decode(response.Var5gAuthData, &AuthData)
	// 	//AuthData, _ := response.Var5gAuthData.(models.EapSession)

	// 	// TS 33.501 A.6, Kseaf derivation function
	// 	FC := UeauCommon.FC_FOR_KSEAF_DERIVATION
	// 	P0 := []byte(CurrentAuthProcedure.ServingNetworkName)
	// 	identity := response.ServingNetworkName // TS 33.501 6.1.3.1, Note of 2.
	// 	Kausf := retrieveEapAkaPrimeKausf(
	// 		CurrentAuthProcedure.ck,
	// 		CurrentAuthProcedure.ik,
	// 		identity,
	// 	) // TS 33.501 6.1.3.1, 10.
	// 	Kseaf := hex.EncodeToString(
	// 		retrieveKseaf(Kausf, FC, P0),
	// 	)

	// 	// TS 29.509 6.1.6.2.7, EapSession, kSeaf
	// 	if AuthData.KSeaf == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.Kseaf:", ERR_MISS_CONDITION)
	// 	} else if AuthData.KSeaf != Kseaf {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.Kseaf:", ERR_VALUE_INCORRECT)
	// 	}
	// 	AuthData.KSeaf = Kseaf

	// 	// TS 29.509 6.1.6.2.7, EapSession, authResult
	// 	if AuthData.AuthResult == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.AuthResult:", ERR_MISS_CONDITION)
	// 	} else if AuthData.AuthResult != models.AuthResult_SUCCESS &&
	// 		AuthData.AuthResult != models.AuthResult_ONGOING &&
	// 		AuthData.AuthResult != models.AuthResult_FAILURE {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.AuthResult:", ERR_VALUE_INCORRECT)
	// 	}

	// 	// TS 29.509 6.1.6.2.7, EapSession, supi
	// 	if AuthData.Supi == "" {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.Supi:", ERR_MISS_CONDITION)
	// 	} else if AuthData.Supi != CurrentAuthProcedure.Suci {
	// 		logger.DetectorLog.Errorln("UeAuthenticationCtx.EapSession.Supi:", ERR_VALUE_INCORRECT)
	// 	}
	// 	AuthData.Supi = CurrentAuthProcedure.Suci

	// 	// response.Var5gAuthData = AuthData

	// } // else if response.AuthType == models.AuthType_EAP_TLS {
	// // assume not support
	// // }

	if response != nil {
		return &HandlerResponse{http.StatusCreated, nil, response}
	} else if problemDetails != nil {
		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}

	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}

// func (p *Processor) PostEapAuthComfirmation(
// 	authCtxId string,
// 	eapSessionReq models.EapSession,
// ) *HandlerResponse {
// 	logger.ProxyLog.Infof("Forward PostEapAuthComfirmation")
// 	// NOTE: The request from AMF is guaranteed to be correct

// 	// TODO: Send request to target NF by setting correct uri
// 	// targetNfUri := "http://ausf.free5gc.org:8000"
// 	scpContext := scp_context.GetSelf()
// 	ausfUri := scpContext.AusfUri
// 	targetNfUri := ausfUri

// 	response, problemDetails, err := p.Consumer().SendEapAuthConfirmRequest(targetNfUri, authCtxId, &eapSessionReq)

// 	if response != nil {
// 		return &HandlerResponse{http.StatusOK, nil, response}
// 	} else if problemDetails != nil {
// 		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
// 	}
// 	logger.DetectorLog.Errorln(err)
// 	problemDetails = &models.ProblemDetails{
// 		Status: http.StatusForbidden,
// 		Cause:  "UNSPECIFIED",
// 	}
// 	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
// }

func (p *Processor) PutUeAutenticationsConfirmation(
	authCtxId string,
	confirmationData models.ConfirmationData,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward AUSF UE Authentication Response")
	// NOTE: The request from AMF is guaranteed to be correct

	// TODO: Send request to target NF by setting correct uri
	// targetNfUri := "http://ausf.free5gc.org:8000"
	scpContext := scp_context.GetSelf()
	ausfUri := scpContext.AusfUri
	targetNfUri := ausfUri

	response, problemDetails, err := p.Consumer().SendAuth5gAkaConfirmRequest(targetNfUri, authCtxId, &confirmationData)

	// TODO: Check IEs in response body is correct
	// 3GPP 29.509 6.1.6.2.8
	if response.AuthResult != models.AuthResult_SUCCESS &&
		response.AuthResult != models.AuthResult_FAILURE &&
		response.AuthResult != models.AuthResult_ONGOING {
		logger.DetectorLog.Errorln("ConfirmationDataResponse.authResult: " + ERR_VALUE_INCORRECT)
	} else if response.AuthResult == models.AuthResult_SUCCESS {
		if response.Supi == "" {
			logger.DetectorLog.Errorln("ConfirmationDataResponse.authResult.Supi: " + ERR_MISS_CONDITION)
			response.Supi = supi
		} else if response.Supi != supi {
			logger.DetectorLog.Errorln("ConfirmationDataResponse.authResult.Supi: " + ERR_VALUE_INCORRECT)
			response.Supi = supi
		}

		// 3GPP 22.501 Annex A.2
		key := append(ck, ik...)
		FC := UeauCommon.FC_FOR_KAUSF_DERIVATION
		P0 := []byte(servingNetworkName)
		P1 := sqnXorAk
		kausf := retrieve5GAkaKausf(key, FC, P0, P1)

		// 3GPP 33.501 Annex A.6
		FC = UeauCommon.FC_FOR_KSEAF_DERIVATION
		P0 = []byte(servingNetworkName)
		kseaf := hex.EncodeToString(retrieveKseaf(kausf, FC, P0))
		if response.Kseaf == "" {
			logger.DetectorLog.Errorln("ConfirmationDataResponse.authResult.Kseaf: " + ERR_MISS_CONDITION)
			response.Kseaf = kseaf
		} else if response.Kseaf != kseaf {
			logger.DetectorLog.Errorln("ConfirmationDataResponse.authResult.Kseaf: " + ERR_VALUE_INCORRECT)
			response.Kseaf = kseaf
		}
	}

	if response != nil {
		return &HandlerResponse{http.StatusOK, nil, response}
	} else if problemDetails != nil {
		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}
