package config

var (
	APIPORT                       int
	API_SECRET                    string
	JWT_TOKEN_LIFESPAN_IN_MINUTES int

	BLOCK_LOGIN_WHEN_EMAIL_IS_NOT_VERIFIED bool

	DBUSER string
	DBPASS string
	DBHOST string
	DBPORT int
	DBNAME string

	FROM_EMAIL         string
	FROM_NAME          string
	ORG_NAME           string
	SENDGRID_API_KEY   string
	EMAIL_TEMPLATE_DIR string
)
