package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	"github.com/praveen-14/user-manager/services/logger"
	"github.com/praveen-14/user-manager/utils"
)

const (
	usersTable      = "users"
	channelCapacity = 100
)

var (
	lock     = &sync.Mutex{}
	instance *Postgres
)

type (
	// Postgres implements the database.Database interface for PostgreSQL.
	Postgres struct {
		db     *sql.DB
		Logger *logger.Service
	}

	rowScanner interface {
		Scan(dest ...any) error
	}
)

// New returns a singleton Postgres instance.
func New() (*Postgres, error) {
	lock.Lock()
	defer lock.Unlock()

	if instance != nil {
		return instance, nil
	}

	db := &Postgres{
		Logger: logger.New("postgres", 0),
	}

	if err := db.connect(); err != nil {
		return nil, err
	}

	instance = db
	return instance, nil
}

func (db *Postgres) connect() error {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.DBHOST,
		config.DBPORT,
		config.DBUSER,
		config.DBPASS,
		config.DBNAME,
		config.PostgresSSLMode,
	)

	sqlDB, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("opening postgres connection: %w", err)
	}

	// Apply conservative pool settings to avoid overwhelming the DB.
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(10 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return fmt.Errorf("pinging postgres: %w", err)
	}

	db.db = sqlDB

	if err := db.ensureSchema(ctx); err != nil {
		sqlDB.Close()
		return err
	}

	return nil
}

// ensureSchema creates the users table and indexes if they do not exist.
func (db *Postgres) ensureSchema(ctx context.Context) error {
	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password TEXT,
			name TEXT,
			mobile_number TEXT,
			role TEXT,
			email_verified BOOLEAN DEFAULT FALSE,
			user_verified BOOLEAN DEFAULT FALSE,
			email_verification_code TEXT,
			password_reset_code TEXT,
			password_reset_requested BOOLEAN DEFAULT FALSE,
			created_at BIGINT,
			updated_at BIGINT,
			last_logged_in_at BIGINT,
			deleted BOOLEAN DEFAULT FALSE,
			token TEXT,
			tags TEXT[] DEFAULT '{}',
			data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON %s (email);
		CREATE INDEX IF NOT EXISTS idx_users_name ON %s (name);
		CREATE INDEX IF NOT EXISTS idx_users_created_at ON %s (created_at);
		CREATE INDEX IF NOT EXISTS idx_users_role ON %s (role);
		CREATE INDEX IF NOT EXISTS idx_users_deleted ON %s (deleted);
		CREATE INDEX IF NOT EXISTS idx_users_tags ON %s USING GIN (tags);
	`, usersTable, usersTable, usersTable, usersTable, usersTable, usersTable, usersTable)

	if _, err := db.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("ensuring postgres schema: %w", err)
	}

	// Add user_verified column if it doesn't exist (migration for existing tables)
	_, err := db.db.ExecContext(ctx, fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = '%s' AND column_name = 'user_verified'
			) THEN
				ALTER TABLE %s ADD COLUMN user_verified BOOLEAN DEFAULT FALSE;
				CREATE INDEX IF NOT EXISTS idx_users_user_verified ON %s (user_verified);
			END IF;
		END $$;
	`, usersTable, usersTable, usersTable))
	if err != nil {
		return fmt.Errorf("adding user_verified column: %w", err)
	}

	return nil
}

// Disconnect closes the database connection.
func (db *Postgres) Disconnect() error {
	if db.db != nil {
		err := db.db.Close()
		db.db = nil
		instance = nil
		return err
	}
	return nil
}

// AddUser inserts a new user record.
func (db *Postgres) AddUser(user models.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tags := pq.StringArray{}
	if user.Tags != nil {
		tags = pq.StringArray(utils.GetUniqueValues(*user.Tags))
	}

	dataJSON, err := marshalData(user.Data)
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("failed to encode user data [ERR=%s]", err))
		return database.ErrBadParams
	}

	_, err = db.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			id, email, password, name, mobile_number, role, email_verified, user_verified,
			email_verification_code, password_reset_code, password_reset_requested,
			created_at, updated_at, last_logged_in_at, deleted, token, tags, data
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
	`, usersTable),
		valueOrNil(user.ID),
		lowerOrNil(user.Email),
		valueOrNil(user.Password),
		lowerOrNil(user.Name),
		valueOrNil(user.MobileNumber),
		valueOrNil(user.Role),
		valueOrNil(user.EmailVerified),
		valueOrNil(user.UserVerified),
		valueOrNil(user.EmailVerificationCode),
		valueOrNil(user.PasswordResetCode),
		valueOrNil(user.PasswordResetRequested),
		valueOrNil(user.CreatedAt),
		valueOrNil(user.UpdatedAt),
		valueOrNil(user.LastLoggedInAt),
		valueOrNil(user.Deleted),
		valueOrNil(user.Token),
		tags,
		dataJSON,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return database.ErrConflict
		}
		db.Logger.Print("FAIL", fmt.Sprintf("adding user failed [ERR=%s]", err))
		return database.ErrBadParams
	}

	return nil
}

// UpdateUser updates user fields and manages tags additions/removals.
func (db *Postgres) UpdateUser(updates models.User, tagsToAdd, tagsToRemove []string) error {
	if updates.ID == nil || *updates.ID == "" {
		return database.ErrBadParams
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	setParts := []string{}
	args := []any{}

	addSet := func(column string, value any) {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", column, len(args)+1))
		args = append(args, value)
	}

	if updates.Email != nil {
		addSet("email", strings.ToLower(*updates.Email))
	}
	if updates.Password != nil {
		addSet("password", *updates.Password)
	}
	if updates.Name != nil {
		addSet("name", strings.ToLower(*updates.Name))
	}
	if updates.MobileNumber != nil {
		addSet("mobile_number", *updates.MobileNumber)
	}
	if updates.Role != nil {
		addSet("role", *updates.Role)
	}
	if updates.EmailVerified != nil {
		addSet("email_verified", *updates.EmailVerified)
	}
	if updates.UserVerified != nil {
		addSet("user_verified", *updates.UserVerified)
	}
	if updates.EmailVerificationCode != nil {
		addSet("email_verification_code", *updates.EmailVerificationCode)
	}
	if updates.PasswordResetCode != nil {
		addSet("password_reset_code", *updates.PasswordResetCode)
	}
	if updates.PasswordResetRequested != nil {
		addSet("password_reset_requested", *updates.PasswordResetRequested)
	}
	if updates.CreatedAt != nil {
		addSet("created_at", *updates.CreatedAt)
	}
	if updates.UpdatedAt != nil {
		addSet("updated_at", *updates.UpdatedAt)
	}
	if updates.LastLoggedInAt != nil {
		addSet("last_logged_in_at", *updates.LastLoggedInAt)
	}
	if updates.Deleted != nil {
		addSet("deleted", *updates.Deleted)
	}
	if updates.Token != nil {
		addSet("token", *updates.Token)
	}
	if updates.Tags != nil {
		addSet("tags", pq.StringArray(utils.GetUniqueValues(*updates.Tags)))
	}
	if updates.Data != nil {
		dataJSON, err := marshalData(updates.Data)
		if err != nil {
			return database.ErrBadParams
		}
		addSet("data", dataJSON)
	}

	if len(setParts) > 0 {
		args = append(args, *updates.ID)
		query := fmt.Sprintf("UPDATE %s SET %s WHERE id = $%d", usersTable, strings.Join(setParts, ", "), len(args))
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			if isUniqueViolation(err) {
				return database.ErrConflict
			}
			return fmt.Errorf("updating user: %w", err)
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			return database.ErrNotFound
		}
	} else {
		// No field updates; ensure user exists before proceeding with tag ops.
		var exists int
		if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE id = $1", usersTable), *updates.ID).Scan(&exists); err != nil {
			if err == sql.ErrNoRows {
				return database.ErrNotFound
			}
			return fmt.Errorf("checking user existence: %w", err)
		}
	}

	if len(tagsToAdd) > 0 {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
			UPDATE %s
			SET tags = (
				SELECT ARRAY(
					SELECT DISTINCT UNNEST(COALESCE(tags, '{}') || $1::text[])
				)
			)
			WHERE id = $2
		`, usersTable), pq.Array(tagsToAdd), *updates.ID); err != nil {
			return fmt.Errorf("adding tags: %w", err)
		}
	}

	if len(tagsToRemove) > 0 {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
			UPDATE %s
			SET tags = (
				SELECT ARRAY(
					SELECT UNNEST(COALESCE(tags, '{}'))
					EXCEPT
					SELECT UNNEST($1::text[])
				)
			)
			WHERE id = $2
		`, usersTable), pq.Array(tagsToRemove), *updates.ID); err != nil {
			return fmt.Errorf("removing tags: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing user update: %w", err)
	}

	return nil
}

// GetUser fetches a user by ID.
func (db *Postgres) GetUser(id string) (models.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1`, selectColumns(), usersTable)
	row := db.db.QueryRow(query, id)
	user, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			db.Logger.Print("INFO", fmt.Sprintf("user not found [id=%s]", id))
			return user, database.ErrNotFound
		}
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed [id=%s, ERR=%s]", id, err))
		return user, database.ErrUnidentified
	}
	return user, nil
}

// GetUserByEmail fetches a user by email.
func (db *Postgres) GetUserByEmail(email string) (models.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE email = $1`, selectColumns(), usersTable)
	row := db.db.QueryRow(query, strings.ToLower(email))
	user, err := scanUser(row)
	if err != nil {
		if err == sql.ErrNoRows {
			db.Logger.Print("INFO", fmt.Sprintf("user not found [email=%s]", email))
			return user, database.ErrNotFound
		}
		db.Logger.Print("FAIL", fmt.Sprintf("getting user by email failed [email=%s, ERR=%s]", email, err))
		return user, database.ErrUnidentified
	}
	return user, nil
}

// GetUsers fetches multiple users by IDs and streams them via a channel.
func (db *Postgres) GetUsers(ids []string) (<-chan *models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dataChan := make(chan *models.User, channelCapacity)

	go func() {
		defer cancel()
		defer close(dataChan)

		query := fmt.Sprintf(`SELECT %s FROM %s WHERE id = ANY($1)`, selectColumns(), usersTable)
		rows, err := db.db.QueryContext(ctx, query, pq.Array(ids))
		if err != nil {
			db.Logger.Print("FAIL", fmt.Sprintf("getting users failed [ids=%+v, ERR=%s]", ids, err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			user, err := scanUser(rows)
			if err != nil {
				db.Logger.Print("FAIL", fmt.Sprintf("decoding user list failed [ERR=%s]", err))
				continue
			}
			dataChan <- &user
		}
	}()

	return dataChan, nil
}

// ReadUsers streams users filtered and sorted based on the request.
func (db *Postgres) ReadUsers(req database.ReadUsersRequest) (database.ReadUsersResponse, error) {
	var res database.ReadUsersResponse

	if req.Skip < 0 || req.Limit < 0 {
		return res, database.ErrBadParams
	}

	sortField, err := resolveSortField(req.SortField)
	if err != nil {
		return res, err
	}
	sortOrder := "ASC"
	if req.SortOrder == database.OrderDesc {
		sortOrder = "DESC"
	}

	clauses := []string{}
	args := []any{}

	if req.Deleted == database.DeletedYes {
		clauses = append(clauses, "deleted = true")
	} else if req.Deleted == database.DeletedNo {
		clauses = append(clauses, "deleted = false")
	}

	if req.CreatedFrom != 0 {
		clauses = append(clauses, fmt.Sprintf("created_at > $%d", len(args)+1))
		args = append(args, req.CreatedFrom)
	}

	if req.CreatedTo != 0 {
		clauses = append(clauses, fmt.Sprintf("created_at < $%d", len(args)+1))
		args = append(args, req.CreatedTo)
	}

	if len(req.Tags) > 0 {
		clauses = append(clauses, fmt.Sprintf("tags @> $%d", len(args)+1))
		args = append(args, pq.Array(req.Tags))
	}

	if len(req.Roles) > 0 {
		clauses = append(clauses, fmt.Sprintf("role = ANY($%d)", len(args)+1))
		args = append(args, pq.Array(req.Roles))
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT %s
		FROM %s
		%s
		ORDER BY %s %s
		LIMIT %d OFFSET %d
	`, selectColumns(), usersTable, where, sortField, sortOrder, req.Limit, req.Skip)

	db.Logger.Print("INFO", fmt.Sprintf("ReadUsers query: %s", strings.ReplaceAll(query, "\n", " ")))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dataChan := make(chan *models.User, channelCapacity)

	go func() {
		defer cancel()
		defer close(dataChan)

		rows, err := db.db.QueryContext(ctx, query, args...)
		if err != nil {
			db.Logger.Print("FAIL", fmt.Sprintf("reading users failed [REQ=%+v, ERR=%s]", req, err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			user, err := scanUser(rows)
			if err != nil {
				db.Logger.Print("FAIL", fmt.Sprintf("decoding user failed [ERR=%s]", err))
				continue
			}
			dataChan <- &user
		}
	}()

	res.ReadResponse.Channel = dataChan
	return res, nil
}

// Helpers

func selectColumns() string {
	return strings.Join([]string{
		"id",
		"email",
		"password",
		"name",
		"mobile_number",
		"role",
		"email_verified",
		"user_verified",
		"email_verification_code",
		"password_reset_code",
		"password_reset_requested",
		"created_at",
		"updated_at",
		"last_logged_in_at",
		"deleted",
		"token",
		"tags",
		"data",
	}, ", ")
}

func scanUser(rs rowScanner) (models.User, error) {
	var (
		id                     sql.NullString
		email                  sql.NullString
		password               sql.NullString
		name                   sql.NullString
		mobileNumber           sql.NullString
		role                   sql.NullString
		emailVerified          sql.NullBool
		userVerified           sql.NullBool
		emailVerificationCode  sql.NullString
		passwordResetCode      sql.NullString
		passwordResetRequested sql.NullBool
		createdAt              sql.NullInt64
		updatedAt              sql.NullInt64
		lastLoggedInAt         sql.NullInt64
		deleted                sql.NullBool
		token                  sql.NullString
		tags                   pq.StringArray
		dataBytes              []byte
	)

	err := rs.Scan(
		&id,
		&email,
		&password,
		&name,
		&mobileNumber,
		&role,
		&emailVerified,
		&userVerified,
		&emailVerificationCode,
		&passwordResetCode,
		&passwordResetRequested,
		&createdAt,
		&updatedAt,
		&lastLoggedInAt,
		&deleted,
		&token,
		&tags,
		&dataBytes,
	)
	if err != nil {
		return models.User{}, err
	}

	user := models.User{}

	if id.Valid {
		user.ID = utils.ToPointer(id.String)
	}
	if email.Valid {
		user.Email = utils.ToPointer(email.String)
	}
	if password.Valid {
		user.Password = utils.ToPointer(password.String)
	}
	if name.Valid {
		user.Name = utils.ToPointer(name.String)
	}
	if mobileNumber.Valid {
		user.MobileNumber = utils.ToPointer(mobileNumber.String)
	}
	if role.Valid {
		user.Role = utils.ToPointer(role.String)
	}
	if emailVerified.Valid {
		user.EmailVerified = utils.ToPointer(emailVerified.Bool)
	}
	if userVerified.Valid {
		user.UserVerified = utils.ToPointer(userVerified.Bool)
	}
	if emailVerificationCode.Valid {
		user.EmailVerificationCode = utils.ToPointer(emailVerificationCode.String)
	}
	if passwordResetCode.Valid {
		user.PasswordResetCode = utils.ToPointer(passwordResetCode.String)
	}
	if passwordResetRequested.Valid {
		user.PasswordResetRequested = utils.ToPointer(passwordResetRequested.Bool)
	}
	if createdAt.Valid {
		user.CreatedAt = utils.ToPointer(createdAt.Int64)
	}
	if updatedAt.Valid {
		user.UpdatedAt = utils.ToPointer(updatedAt.Int64)
	}
	if lastLoggedInAt.Valid {
		user.LastLoggedInAt = utils.ToPointer(lastLoggedInAt.Int64)
	}
	if deleted.Valid {
		user.Deleted = utils.ToPointer(deleted.Bool)
	}
	if token.Valid {
		user.Token = utils.ToPointer(token.String)
	}
	if tags != nil {
		user.Tags = utils.ToPointer([]string(tags))
	}
	if len(dataBytes) > 0 {
		m := map[string]any{}
		if err := json.Unmarshal(dataBytes, &m); err == nil {
			user.Data = utils.ToPointer(m)
		}
	}

	return user, nil
}

func marshalData(data *map[string]any) ([]byte, error) {
	if data == nil || *data == nil {
		return nil, nil
	}
	return json.Marshal(data)
}

func valueOrNil[T any](v *T) any {
	if v == nil {
		return nil
	}
	return *v
}

func lowerOrNil(v *string) any {
	if v == nil {
		return nil
	}
	return strings.ToLower(*v)
}

func isUniqueViolation(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
		return true
	}
	return false
}

func resolveSortField(field database.UserSortField) (string, error) {
	if field == "" || field == database.SortFieldsMap.UserSortFields.Name {
		return "name", nil
	}
	return "", database.ErrBadParams
}
