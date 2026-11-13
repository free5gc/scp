package context

import (
	"slices"

	"github.com/free5gc/openapi/models"
)

// Policies cover the APIs advertised by this SCP's existing serviceList.
// They describe original consumers, not the SCP acting on their behalf.
var servicePolicies = map[models.Nrf_NFMgmt_ServiceName][]models.Nrf_NFMgmt_NFType{
	// TS 29.509 §5.2.2: AMF authentication and UDM authentication-result deregistration.
	models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH: {
		models.Nrf_NFMgmt_NFType_AMF, models.Nrf_NFMgmt_NFType_UDM,
	},
	// TS 29.503 §6.3: Nudm_UEAuthentication is consumed by AUSF.
	models.Nrf_NFMgmt_ServiceName_NUDM_UEAU: {models.Nrf_NFMgmt_NFType_AUSF},
	// TS 29.503 §6.1: Nudm_SubscriberDataManagement consumers; aligned with UDM.
	models.Nrf_NFMgmt_ServiceName_NUDM_SDM: {
		models.Nrf_NFMgmt_NFType_AMF, models.Nrf_NFMgmt_NFType_SMF, models.Nrf_NFMgmt_NFType_UDR,
		models.Nrf_NFMgmt_NFType_UDM, models.Nrf_NFMgmt_NFType_SMSF, models.Nrf_NFMgmt_NFType_GMLC,
		models.Nrf_NFMgmt_NFType_NEF, models.Nrf_NFMgmt_NFType_5_G_DDNMF, models.Nrf_NFMgmt_NFType_NWDAF,
		models.Nrf_NFMgmt_NFType_DCCF, models.Nrf_NFMgmt_NFType_AF,
	},
	// TS 29.504 §5.2: data repository consumers; aligned with UDR.
	models.Nrf_NFMgmt_ServiceName_NUDR_DR: {
		models.Nrf_NFMgmt_NFType_UDM, models.Nrf_NFMgmt_NFType_PCF, models.Nrf_NFMgmt_NFType_NEF,
		models.Nrf_NFMgmt_NFType_NRF, models.Nrf_NFMgmt_NFType_HSS,
	},
}

func AllowedNfTypesForService(serviceName models.Nrf_NFMgmt_ServiceName) ([]models.Nrf_NFMgmt_NFType, bool) {
	allowed, known := servicePolicies[serviceName]
	return slices.Clone(allowed), known
}

func ProducerNFType(serviceName models.Nrf_NFMgmt_ServiceName) (models.Nrf_NFMgmt_NFType, bool) {
	switch serviceName {
	case models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH:
		return models.Nrf_NFMgmt_NFType_AUSF, true
	case models.Nrf_NFMgmt_ServiceName_NUDM_UEAU, models.Nrf_NFMgmt_ServiceName_NUDM_SDM:
		return models.Nrf_NFMgmt_NFType_UDM, true
	case models.Nrf_NFMgmt_ServiceName_NUDR_DR:
		return models.Nrf_NFMgmt_NFType_UDR, true
	default:
		return "", false
	}
}
