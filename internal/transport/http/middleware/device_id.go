package middleware

import (
	"controlplane/pkg/apires"

	"github.com/gin-gonic/gin"
)

// RequireDeviceID xác thực tính liên kết thiết bị (Device Binding).
// Nó kiểm tra sự tồn tại của cookie 'device_id' và đối chiếu với claim 'device_id'
// trong JWT (đã được Access middleware giải mã và inject vào gin context).
//
// Nếu thiếu cookie, thiếu thông tin trong JWT, hoặc hai giá trị này không khớp nhau,
// yêu cầu sẽ bị từ chối với lỗi 400 Bad Request.
func RequireDeviceID() gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceIDCookie, err := c.Cookie("device_id")
		if err != nil {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		deviceIDJWTpayload := GetDeviceID(c)
		if deviceIDJWTpayload == "" {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		if deviceIDCookie != deviceIDJWTpayload {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}
		c.Next()
	}
}
