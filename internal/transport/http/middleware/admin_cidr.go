package middleware

import (
	"iam/pkg/apires"
	"iam/pkg/netutil"

	"github.com/gin-gonic/gin"
)

// AdminCIDR checks if the client IP is allowed based on the provided CIDR whitelist.
func AdminCIDR(allowedCIDRs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !netutil.IsIPAllowed(c.ClientIP(), allowedCIDRs) {
			apires.RespondForbidden(c, "access denied: IP address not in whitelist")
			c.Abort()
			return
		}
		c.Next()
	}
}
