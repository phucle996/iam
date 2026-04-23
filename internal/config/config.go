package config

import "time"

// Config is the root typed config object, loaded once at startup.
type Config struct {
	App       AppCfg
	Security  SecurityCfg
	RateLimit RateLimitCfg
	Psql      PsqlCfg
	Redis     RedisCfg
	GRPC      GRPCCfg
}

// AppCfg holds application-level settings.
type AppCfg struct {
	TimeZone        string
	HTTPPort        int
	LogLV           string
	PublicURL       string
	EnableRateLimit bool
	TrustedProxies  []string
	AllowedOrigins  []string
}

// SecurityCfg holds authentication TTL settings and the root key used to encrypt DB-managed secret versions.
type SecurityCfg struct {
	AccessSecretTTL time.Duration

	OneTimeTokenTTL time.Duration

	RefreshTokenTTL time.Duration

	DeviceActiveTTL time.Duration

	AdminAPITokenTTL          time.Duration
	AdminAPITokenRotateBefore time.Duration

	SecretRotateInterval  time.Duration
	SecretPreviousOverlap time.Duration

	AdminBootstrapTokenPath    string
	AdminBootstrapTokenFileTTL time.Duration

	MasterKey string
}

type RateLimitEndpointCfg struct {
	Capacity int64
	Refill   int64
	Period   time.Duration
}

type RateLimitCfg struct {
	Login   RateLimitEndpointCfg
	Refresh RateLimitEndpointCfg
	Forgot  RateLimitEndpointCfg
	Reset   RateLimitEndpointCfg
	MFA     RateLimitEndpointCfg
	Admin   RateLimitEndpointCfg
}

// PsqlCfg holds PostgreSQL connection parameters.
type PsqlCfg struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	Schema   string
	SSLMode  string

	// TLS
	TLSEnabled bool
	CACertPath string
	CertPath   string
	KeyPath    string

	// Pool
	MaxConns    int
	MinConns    int
	MaxConnLife time.Duration
	MaxConnIdle time.Duration

	// Connection behavior
	PingTimeout   time.Duration
	MaxRetries    int
	RetryInterval time.Duration
}

// RedisCfg holds Redis connection parameters for both cache and stream usage.
type RedisCfg struct {
	Addr     string
	Password string
	DB       int

	// TLS
	TLSEnabled bool
	CACertPath string
	CertPath   string
	KeyPath    string

	// Timeouts
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Pool
	PoolSize     int
	MinIdleConns int

	// Connection behavior
	PingTimeout   time.Duration
	MaxRetries    int
	RetryInterval time.Duration
}

// GRPCCfg holds gRPC server and client settings.
type GRPCCfg struct {
	ServerPort string

	// Inbound server TLS
	ServerTLSEnabled bool
	ServerCertPath   string
	ServerKeyPath    string

	// Dataplane mTLS issuer / verifier
	DataPlaneClientCACertPath      string
	DataPlaneClientCAKeyPath       string
	DataPlaneEnrollToken           string
	DataPlaneClientCertTTL         time.Duration
	DataPlaneHeartbeatInterval     time.Duration
	DataPlaneHeartbeatStaleTimeout time.Duration

	// Client TLS
	ClientTLSEnabled bool
	ClientCACertPath string
	ClientCertPath   string
	ClientKeyPath    string
}

// LoadConfig reads environment variables and returns the root typed config.
func LoadConfig() *Config {
	return &Config{
		App: AppCfg{
			TimeZone:        getEnv("APP_TIMEZONE", "UTC"),
			HTTPPort:        getEnvAsInt("APP_HTTP_PORT", 8080),
			LogLV:           getEnv("APP_LOG_LEVEL", "info"),
			PublicURL:       getEnv("APP_PUBLIC_URL", "http://localhost:8000"),
			EnableRateLimit: getEnvAsBool("APP_ENABLE_RATE_LIMIT", false),
			TrustedProxies:  getEnvAsCSV("APP_TRUSTED_PROXIES", nil),
			AllowedOrigins:  getEnvAsCSV("APP_ALLOWED_ORIGINS", nil),
		},
		Security: SecurityCfg{
			AccessSecretTTL:            15 * time.Minute,
			OneTimeTokenTTL:            15 * time.Minute,
			RefreshTokenTTL:            168 * time.Hour,
			DeviceActiveTTL:            168 * time.Hour,
			AdminAPITokenTTL:           getEnvAsDuration("SECURITY_ADMIN_API_TOKEN_TTL", 15*time.Minute),
			AdminAPITokenRotateBefore:  getEnvAsDuration("SECURITY_ADMIN_API_TOKEN_ROTATE_BEFORE", 5*time.Minute),
			SecretRotateInterval:       getEnvAsDuration("SECURITY_SECRET_ROTATE_INTERVAL", 24*time.Hour),
			SecretPreviousOverlap:      getEnvAsDuration("SECURITY_SECRET_PREVIOUS_OVERLAP", 24*time.Hour),
			AdminBootstrapTokenPath:    getEnv("SECURITY_ADMIN_BOOTSTRAP_TOKEN_PATH", "/run/aurora-iam/bootstrap-admin-token"),
			AdminBootstrapTokenFileTTL: getEnvAsDuration("SECURITY_ADMIN_BOOTSTRAP_TOKEN_FILE_TTL", 5*time.Minute),
			MasterKey:                  getEnv("CORE_SECRET_MASTER_KEY", ""),
		},
		RateLimit: RateLimitCfg{
			Login: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_LOGIN_CAPACITY", 10)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_LOGIN_REFILL", 10)),
				Period:   getEnvAsDuration("RATE_LIMIT_LOGIN_PERIOD", time.Minute),
			},
			Refresh: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_REFRESH_CAPACITY", 20)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_REFRESH_REFILL", 20)),
				Period:   getEnvAsDuration("RATE_LIMIT_REFRESH_PERIOD", time.Minute),
			},
			Forgot: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_FORGOT_CAPACITY", 5)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_FORGOT_REFILL", 5)),
				Period:   getEnvAsDuration("RATE_LIMIT_FORGOT_PERIOD", 5*time.Minute),
			},
			Reset: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_RESET_CAPACITY", 10)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_RESET_REFILL", 10)),
				Period:   getEnvAsDuration("RATE_LIMIT_RESET_PERIOD", 5*time.Minute),
			},
			MFA: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_MFA_CAPACITY", 15)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_MFA_REFILL", 15)),
				Period:   getEnvAsDuration("RATE_LIMIT_MFA_PERIOD", time.Minute),
			},
			Admin: RateLimitEndpointCfg{
				Capacity: int64(getEnvAsInt("RATE_LIMIT_ADMIN_CAPACITY", 10)),
				Refill:   int64(getEnvAsInt("RATE_LIMIT_ADMIN_REFILL", 10)),
				Period:   getEnvAsDuration("RATE_LIMIT_ADMIN_PERIOD", time.Minute),
			},
		},
		Psql: PsqlCfg{
			Host:          getEnv("PSQL_HOST", "localhost"),
			Port:          getEnvAsInt("PSQL_PORT", 5432),
			User:          getEnv("PSQL_USER", "postgres"),
			Password:      getEnv("PSQL_PASSWORD", ""),
			DBName:        getEnv("PSQL_DBNAME", "controlplane"),
			Schema:        getEnv("PSQL_SCHEMA", "iam"),
			SSLMode:       getEnv("PSQL_SSLMODE", "disable"),
			TLSEnabled:    getEnvAsBool("PSQL_TLS_ENABLED", false),
			CACertPath:    getEnv("PSQL_TLS_CA", ""),
			CertPath:      getEnv("PSQL_TLS_CERT", ""),
			KeyPath:       getEnv("PSQL_TLS_KEY", ""),
			MaxConns:      getEnvAsInt("PSQL_MAX_CONNS", 20),
			MinConns:      getEnvAsInt("PSQL_MIN_CONNS", 5),
			MaxConnLife:   getEnvAsDuration("PSQL_MAX_CONN_LIFE", 30*time.Minute),
			MaxConnIdle:   getEnvAsDuration("PSQL_MAX_CONN_IDLE", 5*time.Minute),
			PingTimeout:   getEnvAsDuration("PSQL_PING_TIMEOUT", 5*time.Second),
			MaxRetries:    getEnvAsInt("PSQL_MAX_RETRIES", 5),
			RetryInterval: getEnvAsDuration("PSQL_RETRY_INTERVAL", 3*time.Second),
		},
		Redis: RedisCfg{
			Addr:          getEnv("REDIS_ADDR", "localhost:6379"),
			Password:      getEnv("REDIS_PASSWORD", ""),
			DB:            getEnvAsInt("REDIS_DB", 0),
			TLSEnabled:    getEnvAsBool("REDIS_TLS_ENABLED", false),
			CACertPath:    getEnv("REDIS_TLS_CA", ""),
			CertPath:      getEnv("REDIS_TLS_CERT", ""),
			KeyPath:       getEnv("REDIS_TLS_KEY", ""),
			DialTimeout:   getEnvAsDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:   getEnvAsDuration("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout:  getEnvAsDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
			PoolSize:      getEnvAsInt("REDIS_POOL_SIZE", 20),
			MinIdleConns:  getEnvAsInt("REDIS_MIN_IDLE_CONNS", 5),
			PingTimeout:   getEnvAsDuration("REDIS_PING_TIMEOUT", 5*time.Second),
			MaxRetries:    getEnvAsInt("REDIS_MAX_RETRIES", 5),
			RetryInterval: getEnvAsDuration("REDIS_RETRY_INTERVAL", 3*time.Second),
		},
		GRPC: GRPCCfg{
			ServerPort:                     getEnv("GRPC_SERVER_PORT", "9090"),
			ServerTLSEnabled:               getEnvAsBool("GRPC_SERVER_TLS_ENABLED", false),
			ServerCertPath:                 getEnv("GRPC_SERVER_TLS_CERT", ""),
			ServerKeyPath:                  getEnv("GRPC_SERVER_TLS_KEY", ""),
			DataPlaneClientCACertPath:      getEnv("GRPC_DATAPLANE_CLIENT_CA", ""),
			DataPlaneClientCAKeyPath:       getEnv("GRPC_DATAPLANE_CLIENT_CA_KEY", ""),
			DataPlaneEnrollToken:           getEnv("GRPC_DATAPLANE_ENROLL_TOKEN", ""),
			DataPlaneClientCertTTL:         getEnvAsDuration("GRPC_DATAPLANE_CLIENT_CERT_TTL", 30*24*time.Hour),
			DataPlaneHeartbeatInterval:     getEnvAsDuration("GRPC_DATAPLANE_HEARTBEAT_INTERVAL", 30*time.Second),
			DataPlaneHeartbeatStaleTimeout: getEnvAsDuration("GRPC_DATAPLANE_STALE_TIMEOUT", 2*time.Minute),
			ClientTLSEnabled:               getEnvAsBool("GRPC_CLIENT_TLS_ENABLED", false),
			ClientCACertPath:               getEnv("GRPC_CLIENT_TLS_CA", ""),
			ClientCertPath:                 getEnv("GRPC_CLIENT_TLS_CERT", ""),
			ClientKeyPath:                  getEnv("GRPC_CLIENT_TLS_KEY", ""),
		},
	}
}
