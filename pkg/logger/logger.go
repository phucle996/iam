package logger

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Context keys used by middleware to inject request-scoped values.
const (
	KeyRequestID = "request_id"
	KeyUserID    = "user_id"
)

// Log type constants.
const (
	LogTypeAccess  = "access"
	LogTypeHandler = "handler"
	LogTypeSystem  = "system"
)

// Global logger instance.
var log *logrus.Logger

// InitLogger initializes the global logger from config.
// Output: JSON, timestamp RFC3339Nano UTC, output os.Stderr.
func InitLogger() {
	log = logrus.New()
	log.SetOutput(os.Stderr)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	log.SetLevel(logrus.InfoLevel)
}

// L returns the global logrus logger (for non-request contexts like startup).
func L() *logrus.Logger {
	if log == nil {
		// fallback: not yet initialized
		log = logrus.New()
		log.SetOutput(os.Stderr)
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	}
	return log
}

// --- Helper: extract from gin.Context ---

func requestID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	v, _ := c.Get(KeyRequestID)
	s, _ := v.(string)
	return s
}

func userID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	v, _ := c.Get(KeyUserID)
	s, _ := v.(string)
	return s
}

// --- Access Log ---

// AccessLog emits a structured access log entry (log_type=access, event=completed).
func AccessLog(c *gin.Context, op, message, errorCode, method, route string, statusCode int, latencyMs float64, clientIP string) {
	L().WithFields(logrus.Fields{
		"log_type":    LogTypeAccess,
		"request_id":  requestID(c),
		"op":          op,
		"event":       "completed",
		"message":     message,
		"error_code":  errorCode,
		"method":      method,
		"route":       route,
		"status_code": statusCode,
		"latency_ms":  latencyMs,
		"client_ip":   clientIP,
	}).Info("access")
}

// --- Handler Log ---

// HandlerInfo emits a handler-level info log.
func HandlerInfo(c *gin.Context, op, message string) {
	L().WithFields(logrus.Fields{
		"log_type":   LogTypeHandler,
		"request_id": requestID(c),
		"user_id":    userID(c),
		"op":         op,
	}).Info(message)
}

// HandlerWarn emits a handler-level warn log.
func HandlerWarn(c *gin.Context, op string, err error, message string) {
	fields := logrus.Fields{
		"log_type":   LogTypeHandler,
		"request_id": requestID(c),
		"user_id":    userID(c),
		"op":         op,
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	L().WithFields(fields).Warn(message)
}

// HandlerError emits a handler-level error log.
func HandlerError(c *gin.Context, op string, err error) {
	fields := logrus.Fields{
		"log_type":   LogTypeHandler,
		"request_id": requestID(c),
		"user_id":    userID(c),
		"op":         op,
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	L().WithFields(fields).Error("handler error")
}

// --- System Log (startup, shutdown, infra — no gin context) ---

// SysInfo emits a system-level info log.
func SysInfo(op, message string) {
	L().WithFields(logrus.Fields{
		"log_type": LogTypeSystem,
		"op":       op,
	}).Info(message)
}

// SysWarn emits a system-level warn log.
func SysWarn(op, message string) {
	L().WithFields(logrus.Fields{
		"log_type": LogTypeSystem,
		"op":       op,
	}).Warn(message)
}

// SysError emits a system-level error log.
func SysError(op, message string) {
	L().WithFields(logrus.Fields{
		"log_type": LogTypeSystem,
		"op":       op,
	}).Error(message)
}

// SysFatal emits a system-level fatal log and exits.
func SysFatal(op, message string) {
	L().WithFields(logrus.Fields{
		"log_type": LogTypeSystem,
		"op":       op,
	}).Fatal(message)
}
