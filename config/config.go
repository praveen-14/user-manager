package config

import (
	"os"
	"strconv"

	rootconfig "resource_allocator/config"
)

var (
	APIPORT                       int
	API_SECRET                    string
	JWT_TOKEN_LIFESPAN_IN_MINUTES int

	BLOCK_LOGIN_WHEN_EMAIL_IS_NOT_VERIFIED bool

	// Postgres configuration (aligned with root config)
	DBUSER = getEnvOrDefault("DB_USER", rootconfig.DBUser)
	DBPASS = getEnvOrDefault("DB_PASSWORD", rootconfig.DBPassword)
	DBHOST = getEnvOrDefault("DB_HOST", rootconfig.DBHost)
	DBPORT = getEnvIntOrDefault("DB_PORT", rootconfig.DBPort)
	DBNAME = getEnvOrDefault("DB_NAME", rootconfig.DBName)

	PostgresSSLMode = getEnvOrDefault("POSTGRES_SSLMODE", "disable")

	FROM_EMAIL         string
	FROM_NAME          string
	ORG_NAME           string
	SENDGRID_API_KEY   string
	EMAIL_TEMPLATE_DIR string

	// MongoDB configuration (for compatibility - not used, app uses PostgreSQL)
	// These are kept to prevent compilation errors in mongodb.go
	MongoDBHost     = rootconfig.MongoDBHost
	MongoDBPort     = rootconfig.MongoDBPort
	MongoDBName     = rootconfig.MongoDBName
	MongoDBUser     = rootconfig.MongoDBUser
	MongoDBPassword = rootconfig.MongoDBPassword
)

// getEnvOrDefault returns the environment variable value or the default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvIntOrDefault returns the environment variable value as int or the default if not set
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
