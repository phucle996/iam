package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// getEnv reads an environment variable or returns a default value.
func getEnv(key, defaultVal string) string {
	val := os.Getenv(key)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	// Strip quotes if present
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	if val == "" {
		return defaultVal
	}
	return val
}

// getEnvAsInt reads an environment variable as int or returns a default.
func getEnvAsInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	// Strip quotes
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}

// getEnvAsBool reads an environment variable as bool or returns a default.
func getEnvAsBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	// Strip quotes
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return b
}

// getEnvAsDuration reads an environment variable as time.Duration or returns a default.
func getEnvAsDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	// Strip quotes
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return defaultVal
	}
	return d
}

// getEnvAsCSV reads a comma-separated env var as []string.
func getEnvAsCSV(key string, defaultVal []string) []string {
	val := os.Getenv(key)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	// Strip quotes
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}

	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return defaultVal
	}
	return out
}
