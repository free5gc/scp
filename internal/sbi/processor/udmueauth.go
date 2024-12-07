package processor

import (
	"encoding/hex"
	"net/http"

	"github.com/antihax/optional"
	"github.com/free5gc/UeauCommon"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/gin-gonic/gin"
)

func (p *Processor) PostGenerateAuthData(
	supiOrSuci string,
	authInfo models.AuthenticationInfoRequest,
) *HandlerResponse {
	logger.ProxyLog.Infof("Forward UDM UE Authentication Request")

	// NOTE: The request from AMF is guaranteed to be correct

	// TODO: Send request to target NF by setting correct uri
	// targetNfUri := "http://udm.free5gc.org:8000"
	scpContext := scp_context.GetSelf()
	udmUri := scpContext.UdmUri
	targetNfUri := udmUri

	// TODO: Check IEs in request body is correct
	// 3GPP 29.503 6.3.6.2.2
	if authInfo.ServingNetworkName == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName:", ERR_MANDATORY_ABSENT)
	} else if authInfo.ServingNetworkName != CurrentAuthProcedure.ServingNetworkName {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName:", ERR_VALUE_INCORRECT)
	}
	authInfo.ServingNetworkName = CurrentAuthProcedure.ServingNetworkName

	// TODO: Send request to target NF by setting correct uri
	supi, _ = extractSupi(supiOrSuci)

	response, problemDetails, err := p.Consumer().SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfo)
	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	_, _, _, _, _ = xres, sqnXorAk, ck, ik, autn

	// Store correct data in SCP detector
	CurrentAuthProcedure.AuthenticationVector.Xres = hex.EncodeToString(xres)
	CurrentAuthProcedure.sqnXorAk = sqnXorAk
	CurrentAuthProcedure.ck = ck
	CurrentAuthProcedure.ik = ik
	CurrentAuthProcedure.AuthenticationVector.Autn = hex.EncodeToString(autn)
	// logger.DetectorLog.Errorln("Xres: ", CurrentAuthProcedure.AuthenticationVector.Xres)
	// logger.DetectorLog.Errorln("Autn: ", CurrentAuthProcedure.AuthenticationVector.Autn)

	// TODO: Check IEs in response body is correct

	// TS 29.503 6.3.6.2.3, AuthenticationInfoResult, authType
	if response.AuthType == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthType:", ERR_MANDATORY_ABSENT)
	} else if response.AuthType != models.AuthType(CurrentAuthProcedure.AuthSubsData.AuthenticationMethod) {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthType:", ERR_VALUE_INCORRECT)
	}
	response.AuthType = models.AuthType(CurrentAuthProcedure.AuthSubsData.AuthenticationMethod)
	// TS 29.503 Figure 6.3.3.1-1  Nudm_UEAU API
	CurrentAuthProcedure.Supi, _ = extractSupi(supiOrSuci) // store correct data in SCP detector

	// TS 29.503 6.3.6.2.3, AuthenticationInfoResult, supi
	if response.Supi == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.Supi:", ERR_MISS_CONDITION)
	} else if response.Supi != CurrentAuthProcedure.Supi {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.Supi:", ERR_VALUE_INCORRECT)
	}
	response.Supi = CurrentAuthProcedure.Supi

	// TS 29.503 6.3.6.2.3, AuthenticationInfoResult, authenticationVector
	if response.AuthenticationVector == nil {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector:", ERR_MISS_CONDITION)
	}

	// TS 29.503 6.3.6.2.5, AvEapAkaPrime or Av5GHeAka, rand
	// Assume rand from UDM is correct
	CurrentAuthProcedure.AuthenticationVector.Rand = response.AuthenticationVector.Rand // store correct data in SCP detector

	// TS 29.503 6.3.6.2.5, AvEapAkaPrime or Av5GHeAka, autn
	if response.AuthenticationVector.Autn == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Autn:", ERR_MANDATORY_ABSENT)
	} else if response.AuthenticationVector.Autn != CurrentAuthProcedure.AuthenticationVector.Autn {
		logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Autn:", ERR_VALUE_INCORRECT)
	}
	response.AuthenticationVector.Autn = CurrentAuthProcedure.AuthenticationVector.Autn

	// TS 29.509 6.1.6.3.3
	if response.AuthType == models.AuthType__5_G_AKA {

		// TS 29.503 6.3.6.2.5, Av5GHeAka, avType
		if response.AuthenticationVector.AvType == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.AvType != models.AvType__5_G_HE_AKA {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.AvType = models.AvType__5_G_HE_AKA

		// TS 33.501 A.4, RES* and XRES* derivation function
		key := append(CurrentAuthProcedure.ck, CurrentAuthProcedure.ik...)
		FC := UeauCommon.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
		P0 := []byte(CurrentAuthProcedure.ServingNetworkName)
		P1, _ := hex.DecodeString(CurrentAuthProcedure.AuthenticationVector.Rand)
		P2, _ := hex.DecodeString(CurrentAuthProcedure.AuthenticationVector.Xres)
		CurrentAuthProcedure.AuthenticationVector.XresStar =
			hex.EncodeToString(
				retrieveXresStar(key, FC, P0, P1, P2),
			) // store correct data in SCP detector

		// TS 29.503 6.3.6.2.5, Av5GHeAka, xresStar
		if response.AuthenticationVector.XresStar == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.XresStar:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.XresStar != CurrentAuthProcedure.AuthenticationVector.XresStar {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.XresStar:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.XresStar = CurrentAuthProcedure.AuthenticationVector.XresStar

		// TS 33.501 A.2, Kausf derivation function
		FC = UeauCommon.FC_FOR_KAUSF_DERIVATION
		P1 = CurrentAuthProcedure.sqnXorAk
		CurrentAuthProcedure.AuthenticationVector.Kausf =
			hex.EncodeToString(
				retrieve5GAkaKausf(key, FC, P0, P1),
			) // store correct data in SCP detector

		// TS 29.503 6.3.6.2.5, Av5GHeAka, kausf
		if response.AuthenticationVector.Kausf == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Kausf:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.Kausf != CurrentAuthProcedure.AuthenticationVector.Kausf {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Kausf:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.Kausf = CurrentAuthProcedure.AuthenticationVector.Kausf

	} else if response.AuthType == models.AuthType_EAP_AKA_PRIME {

		// TS 29.503 6.3.6.2.4, AvEapAkaPrime, avType
		if response.AuthenticationVector.AvType == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.AvType != models.AvType_EAP_AKA_PRIME {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.AvType = models.AvType_EAP_AKA_PRIME

		// TS 29.503 6.3.6.2.4, AvEapAkaPrime, xres
		if response.AuthenticationVector.Xres == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Xres:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.Xres != CurrentAuthProcedure.AuthenticationVector.Xres {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Xres:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.Xres = CurrentAuthProcedure.AuthenticationVector.Xres

		// TS 33.402 A.2, Function for the derivation of CK’, IK’ from CK, IK
		key := append(CurrentAuthProcedure.ck, CurrentAuthProcedure.ik...)
		FC := UeauCommon.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
		P0 := []byte(CurrentAuthProcedure.ServingNetworkName) // TS 33.501 A.3
		P1 := CurrentAuthProcedure.sqnXorAk
		ckPrime, ikPrime := retrieveCkPrimeAndIkPrime(key, FC, P0, P1)

		// Store correct data in SCP detector
		CurrentAuthProcedure.AuthenticationVector.CkPrime = hex.EncodeToString(ckPrime)
		CurrentAuthProcedure.AuthenticationVector.IkPrime = hex.EncodeToString(ikPrime)

		// TS 29.503 6.3.6.2.4, AvEapAkaPrime, ckPrime
		if response.AuthenticationVector.CkPrime == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.CkPrime:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.CkPrime != CurrentAuthProcedure.AuthenticationVector.CkPrime {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.CkPrime:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.CkPrime = CurrentAuthProcedure.AuthenticationVector.CkPrime

		// TS 29.503 6.3.6.2.4, AvEapAkaPrime, ikPrime
		if response.AuthenticationVector.IkPrime == "" {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.IkPrime:", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.IkPrime != CurrentAuthProcedure.AuthenticationVector.IkPrime {
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.IkPrime:", ERR_VALUE_INCORRECT)
		}
		response.AuthenticationVector.IkPrime = CurrentAuthProcedure.AuthenticationVector.IkPrime

	} //else if response.AuthType == models.AuthType_EAP_TLS {
	// assume not support
	// }

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
	logger.DetectorLog.Errorln("end")
	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}

func (p *Processor) ConfirmAuthDataProcedure(
	gc *gin.Context,
	authEvent models.AuthEvent,
	supi string,
) {
	ctx, pd, err := p.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		gc.JSON(int(pd.Status), pd)
		return
	}
	var createAuthParam Nudr_DataRepository.CreateAuthenticationStatusParamOpts
	optInterface := optional.NewInterface(authEvent)
	createAuthParam.AuthEvent = optInterface

	client, err := p.Consumer().CreateSCPClientToUDR(supi)
	if err != nil {
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	resp, err := client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(
		ctx, supi, &createAuthParam)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: int32(resp.StatusCode),
			Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
			Detail: err.Error(),
		}

		logger.DetectorLog.Errorln("ConfirmAuth err:", err.Error())
		gc.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.DetectorLog.Errorf("CreateAuthenticationStatus response body cannot close: %+v", rspCloseErr)
		}
	}()

	gc.Status(http.StatusCreated)
}
