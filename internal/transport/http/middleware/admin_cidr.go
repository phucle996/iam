package middleware

import (
	"net"
	"strings"

	"iam/pkg/apires"

	"github.com/gin-gonic/gin"
)

func AdminCIDR(allowedCIDRs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isIPAllowed(c.ClientIP(), allowedCIDRs) {
			apires.RespondForbidden(c, "access denied: IP address not in whitelist")
			c.Abort()
			return
		}
		c.Next()
	}
}

func isIPAllowed(ipText string, cidrs []string) bool {
	cleaned := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			cleaned = append(cleaned, cidr)
		}
	}
	if len(cleaned) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(ipText))
	if ip == nil {
		return false
	}
	for _, cidr := range cleaned {
		if _, block, err := net.ParseCIDR(cidr); err == nil && block.Contains(ip) {
			return true
		}
		if exact := net.ParseIP(cidr); exact != nil && exact.Equal(ip) {
			return true
		}
	}
	return false
}
