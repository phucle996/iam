package config

import "time"

// Config is the root typed config object, loaded once at startup.
type Config struct {
	App      AppCfg
	Security SecurityCfg
	Psql     PsqlCfg
	Redis    RedisCfg
	GRPC     GRPCCfg
	Telegram TelegramCfg
}

// AppCfg holds application-level settings.
type AppCfg struct {
	TimeZone           string
	HTTPPort           int
	LogLV              string
	PublicURL          string
	TrustedProxies     []string
	AllowedOrigins     []string
	OAuthAllowedScopes []string
}

// SecurityCfg holds authentication TTL settings and the root key used to encrypt DB-managed secret versions.
type SecurityCfg struct {
	AccessSecretTTL time.Duration

	OneTimeTokenTTL time.Duration

	RefreshTokenTTL time.Duration

	DeviceActiveTTL time.Duration

	AdminSessionTTL        time.Duration
	AdminTrustedDeviceTTL  time.Duration
	AdminCredentialLockTTL time.Duration
	AdminMaxFailedAttempts int
	AdminAllowedCIDRs      []string

	SecretRotateInterval  time.Duration
	SecretPreviousOverlap time.Duration

	OAuthAuthorizationCodeTTL time.Duration

	MasterKey string
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

// TelegramCfg holds Telegram bot settings.
type TelegramCfg struct {
	BotToken string
	ChatID   string
}

// GRPCCfg holds IAM internal gRPC server settings.
type GRPCCfg struct {
	Enabled bool

	ServerPort string

	ServerTLSCertPath string
	ServerTLSKeyPath  string
	ClientCACertPath  string
}

// LoadConfig reads environment variables and returns the root typed config.
func LoadConfig() *Config {
	return &Config{
		App: AppCfg{
			TimeZone:       getEnv("APP_TIMEZONE", "UTC"),
			HTTPPort:       getEnvAsInt("APP_HTTP_PORT", 8080),
			PublicURL:      getEnv("APP_PUBLIC_URL", "http://localhost:8000"),
			TrustedProxies: getEnvAsCSV("APP_TRUSTED_PROXIES", nil),
			AllowedOrigins: getEnvAsCSV("APP_ALLOWED_ORIGINS", nil),
			OAuthAllowedScopes: getEnvAsCSV("APP_OAUTH_ALLOWED_SCOPES", []string{
				"profile",
				"email",
				"offline_access",
			}),
		},
		Security: SecurityCfg{
			AccessSecretTTL:           15 * time.Minute,
			OneTimeTokenTTL:           15 * time.Minute,
			RefreshTokenTTL:           168 * time.Hour,
			DeviceActiveTTL:           168 * time.Hour,
			AdminSessionTTL:           12 * time.Hour,
			AdminTrustedDeviceTTL:     30 * 24 * time.Hour,
			AdminCredentialLockTTL:    15 * time.Minute,
			AdminMaxFailedAttempts:    5,
			AdminAllowedCIDRs:         getEnvAsCSV("ADMIN_ALLOWED_CIDRS", []string{"0.0.0.0/0", "::/0"}),
			SecretRotateInterval:      24 * time.Hour,
			SecretPreviousOverlap:     24 * time.Hour,
			OAuthAuthorizationCodeTTL: 5 * time.Minute,
			MasterKey:                 getEnv("CORE_SECRET_MASTER_KEY", "dev-master-key-only-for-dev"),
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
			Enabled:           getEnvAsBool("GRPC_SERVER_ENABLED", false),
			ServerPort:        getEnv("GRPC_SERVER_PORT", "9090"),
			ServerTLSCertPath: getEnv("GRPC_SERVER_TLS_CERT", ""),
			ServerTLSKeyPath:  getEnv("GRPC_SERVER_TLS_KEY", ""),
			ClientCACertPath:  getEnv("GRPC_SERVER_CLIENT_CA", ""),
		},
		Telegram: TelegramCfg{
			BotToken: getEnv("TELEGRAM_BOT_TOKEN", ""),
			ChatID:   getEnv("TELEGRAM_CHAT_ID", ""),
		},
	}
}
