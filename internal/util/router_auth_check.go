package util

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/free5gc/openapi/models"
	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/gin-gonic/gin"
)

type RouterAuthorizationCheck struct {
	serviceName models.Nrf_NFMgmt_ServiceName
	realm       string
}

func NewRouterAuthorizationCheck(
	serviceName models.Nrf_NFMgmt_ServiceName, apiURI string,
) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{serviceName: serviceName, realm: apiURI}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, scpContext scp_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	if err := scpContext.AuthorizationCheck(token, rac.serviceName); err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Unauthorized: %s", err.Error())
		status := http.StatusUnauthorized
		challenge := "Bearer realm=" + strconv.Quote(rac.realm)
		// The pinned OpenAPI version exposes insufficient scope through this error message.
		if err.Error() == "OAuth scope verification failed: insufficient permissions" {
			status = http.StatusForbidden
			challenge += `, error="insufficient_scope", scope=` + strconv.Quote(string(rac.serviceName))
		} else if strings.TrimSpace(token) != "" {
			challenge += `, error="invalid_token"`
		}
		c.Header("WWW-Authenticate", challenge)
		c.JSON(status, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Authorized")
}
