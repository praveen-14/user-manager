package arangodb

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"user-manager/config"
	"user-manager/database"
	"user-manager/database/models"
	"user-manager/services/logger"
	"user-manager/utils"

	ara "github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"
)

var (
	lock            = &sync.Mutex{}
	instance        *AraDatabase
	channelCapacity = 100
)

const (
	UsersColName = "users"
)

type (
	Config struct {
		Host     string `json:"host"`     //database host
		Port     int    `json:"port"`     //data connect port
		Username string `json:"username"` //database username
		Password string `json:"password"` //database password
		DBName   string `json:"dbName"`   //database name
	}

	AraDatabase struct {
		Config
		Logger *logger.Service

		client ara.Client
		DB     ara.Database
	}

	Index struct {
		*ara.EnsurePersistentIndexOptions
		Fields []string
	}
)

func New() (*AraDatabase, error) {
	lock.Lock()
	defer lock.Unlock()
	if instance == nil {

		instance = &AraDatabase{
			Logger: logger.New("ara-database", 0),
			Config: Config{
				Host:     config.DBHOST,
				Port:     config.DBPORT,
				Username: config.DBUSER,
				Password: config.DBPASS,
				DBName:   config.DBNAME,
			},
		}
		err := instance.Connect()
		if err != nil {
			instance.Logger.Print("FAIL", fmt.Sprintf("could not connect to database [ERR: %s]", err))
			return instance, err
		}
	}
	return instance, nil
}

func (db *AraDatabase) Disconnect() error {
	return nil
}

func (db *AraDatabase) Connect() error {

	connection, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{fmt.Sprintf("http://%s:%d", db.Config.Host, db.Config.Port)},
	})
	if err != nil {
		return fmt.Errorf("creating database connection [ERR: %s]", err)
	}

	db.client, err = ara.NewClient(ara.ClientConfig{
		Connection:     connection,
		Authentication: ara.BasicAuthentication(db.Username, db.Password),
	})
	if err != nil {
		return fmt.Errorf("creating database client [ERR: %s]", err)
	}

	db.DB, err = db.client.Database(context.Background(), db.Config.DBName)
	if err != nil {
		return fmt.Errorf("Database not found. Database should be created before using this API")
	}

	return nil
}

// CRUD Users

func (db *AraDatabase) AddUser(user models.User) error {

	if _, err := db.Put(UsersColName, user, false); err == nil {
		db.Logger.Print("INFO", fmt.Sprintf("user saved, id = %s", *user.ID))
	} else {
		db.Logger.Print("FAIL", "user insertion failed, id = %s, err = %s", user.ID, err)
		return err
	}

	return nil
}

func (db *AraDatabase) UpdateUser(user *models.User) error {

	if err := db.Update(UsersColName, *user.ID, user); err == nil {
		db.Logger.Print("INFO", fmt.Sprintf("user saved, id = %s", *user.ID))
	} else {
		db.Logger.Print("FAIL", "user insertion failed, id = %s, err = %s", user.ID, err)
		return err
	}

	return nil
}

func (db *AraDatabase) GetUser(id string) (user *models.User, err error) {

	if err := db.Get(UsersColName, id, user); err == nil {
		db.Logger.Print("INFO", fmt.Sprintf("got user, id = %s", id))
	} else {
		db.Logger.Print("FAIL", "getting user failed, id = %s, err = %s", id, err)
		return user, err
	}

	return user, nil
}

func (db *AraDatabase) UserExists(id string) (exists bool, err error) {
	return db.Exists(UsersColName, id)
}

func (db *AraDatabase) ReadUsers(req database.ReadUsersRequest) (res database.ReadUsersResponse, err error) {

	dataChan := make(chan *models.User, channelCapacity)

	queries := []string{}
	if req.SortField != "" && req.SortOrder != "" {
		queries = append(queries, fmt.Sprintf("SORT x.%s %s", req.SortField, req.SortOrder))
	}
	queries = genDeletedQuery(queries, req.Deleted)
	queries, err = genReadQuery(queries, req.ReadRequest)
	if err != nil {
		db.Logger.Print("FAIL", "failed to genrate query, req = %+v, err = %s", req, err)
		return res, err
	}

	go func() {
		defer close(dataChan)

		cur, err := db.Query(UsersColName, queries)
		if err != nil {
			db.Logger.Print("FAIL", "reading companies failed, req = %+v, err = %s", req, err)
			return
		}

		for cur.HasMore() {
			company := &models.User{}
			_company := map[string]interface{}{}
			if _, err = cur.ReadDocument(context.Background(), &_company); err != nil {
				db.Logger.Fatalf("reading companies [ERR: %s]", err)
			}
			decode(_company, company)
			dataChan <- company
		}

	}()

	res.ReadResponse.Channel = dataChan

	return res, nil
}

// converts struct to map (id is renamed to _key)
func encode(obj any) any {
	dict := utils.ToDict(obj)
	dict["_key"] = dict["id"]
	delete(dict, "id")
	return dict
}

// converts map to given type (_key is renamed to id)
func decode(_obj map[string]interface{}, objPointer any) {
	_obj["id"] = _obj["_key"]
	delete(_obj, "_key")
	utils.ToObj(_obj, objPointer)
}

func genReadQuery(currQueries []string, req database.ReadRequest) ([]string, error) {
	queries := []string{}

	if req.CreatedFrom != 0 {
		queries = append(queries, fmt.Sprintf("FILTER x.created_at >= %d", req.CreatedFrom))
	}

	if req.CreatedTo != 0 {
		queries = append(queries, fmt.Sprintf("FILTER x.created_at < %d", req.CreatedTo))
	}

	queries = append(queries, currQueries...)

	if req.Skip < 0 || req.Limit < 0 {
		return nil, database.ErrBadParams
	}
	queries = append(queries, fmt.Sprintf("LIMIT %d, %d", req.Skip, req.Limit))

	return queries, nil
}

func genDeletedQuery(queries []string, deletedStatus database.DeletedStatus) []string {
	if deletedStatus == database.DeletedYes {
		queries = append(queries, "FILTER x.is_active == true")
	} else if deletedStatus == database.DeletedNo {
		queries = append(queries, "FILTER x.is_active == false")
	}
	return queries
}

// Query allows you to query the database.
func (db *AraDatabase) Query(collection string, queries []string) (cur ara.Cursor, err error) {

	query := fmt.Sprintf(`
		FOR x IN %s
			%s
		RETURN x
		`, collection, strings.Join(queries, "\n"))

	db.Logger.Print("INFO", "query = %s", query)

	ctx := ara.WithQueryStream(context.Background())
	ctx = ara.WithQueryTTL(ctx, time.Hour)
	cur, err = db.DB.Query(ctx, query, nil)

	if err != nil {
		db.Logger.Print("FAIL", "querying documents failed, query = %s, err = %s", query, err)
		return cur, err
	}

	return cur, nil
}

// Checks existence
func (db *AraDatabase) Exists(collection string, id string) (exists bool, err error) {

	col, err := db.DB.Collection(context.Background(), collection)
	if err != nil {
		return false, fmt.Errorf("connecting to collection %s [ERR: %s]", collection, err)
	}

	exists, err = col.DocumentExists(
		context.Background(),
		id,
	)

	if err != nil {
		return false, fmt.Errorf("checking document existence failed in collection %s [ERR: %s]", collection, err)
	}

	return exists, nil
}

// update document
func (db *AraDatabase) Update(collection string, id string, update any) (err error) {

	col, err := db.DB.Collection(context.Background(), collection)
	if err != nil {
		return fmt.Errorf("connecting to collection %s [ERR: %s]", collection, err)
	}

	_, err = col.UpdateDocument(
		context.Background(),
		id,
		encode(update),
	)

	if err != nil {
		if ara.IsArangoErrorWithErrorNum(err, ara.ErrArangoDocumentNotFound) {
			return database.ErrNotFound
		} else {
			return fmt.Errorf("updating document failed in collection %s [ERR: %s]", collection, err)
		}
	}

	return nil
}

// Gets a document by _key
func (db *AraDatabase) Get(collection string, _key string, out any) (err error) {

	col, err := db.DB.Collection(context.Background(), collection)
	if err != nil {
		return fmt.Errorf("connecting to collection %s [ERR: %s]", collection, err)
	}

	_out := map[string]interface{}{}
	_, err = col.ReadDocument(
		context.Background(),
		_key,
		&_out,
	)

	if err != nil {
		if ara.IsArangoErrorWithErrorNum(err, ara.ErrArangoDocumentNotFound) {
			return database.ErrNotFound
		} else {
			return fmt.Errorf("getting document in collection %s [ERR: %s]", collection, err)
		}
	}

	decode(_out, out)

	return nil
}

// Put creates a new document
func (db *AraDatabase) Put(collection string, doc interface{}, upsert bool) (id string, err error) {

	col, err := db.DB.Collection(context.Background(), collection)
	if err != nil {
		return "", fmt.Errorf("connecting to collection %s [ERR: %s]", collection, err)
	}

	ctx := context.Background()
	if upsert {
		ctx = ara.WithOverwrite(ctx)
	}
	meta, err := col.CreateDocument(
		ara.WithWaitForSync(ctx),
		encode(doc),
	)
	if err != nil {
		if ara.IsArangoErrorWithErrorNum(err, ara.ErrArangoUniqueConstraintViolated) {
			return "", database.ErrConflict
		} else {
			return "", fmt.Errorf("creating document in collection %s [ERR: %s]", collection, err)
		}

	}
	id = meta.Key

	return id, nil
}

// CreateDatabase
func (db *AraDatabase) CreateDatabase(name string) error {

	DB, err := db.client.CreateDatabase(context.Background(), name, &ara.CreateDatabaseOptions{
		Users: []ara.CreateDatabaseUserOptions{
			{
				UserName: config.DBUSER,
				Password: config.DBPASS,
			},
		},
	})
	if err != nil {
		return err
	}

	db.DB = DB

	return nil
}

// CreateCollection
func (db *AraDatabase) CreateCollection(dbName, collection string, opts *ara.CreateCollectionOptions) error {

	_db, err := db.client.Database(context.Background(), dbName)
	if err != nil {
		return err
	}

	if opts != nil {
		_, err = _db.CreateCollection(context.Background(), collection, opts)
	} else {
		_, err = _db.CreateCollection(context.Background(), collection, &ara.CreateCollectionOptions{
			WaitForSync: true,
		})
	}

	if err != nil {
		return err
	}

	return nil
}

// CreateIndex create a new hash type index on collection
func (db *AraDatabase) CreateIndex(collection string, opts *Index) (err error) {
	if db.DB == nil {
		return fmt.Errorf("database not connected")
	}

	col, err := db.DB.Collection(context.Background(), collection)
	if err != nil {
		return err
	}

	_, _, err = col.EnsurePersistentIndex(context.Background(), opts.Fields, opts.EnsurePersistentIndexOptions)
	if err != nil {
		return err
	}

	return nil
}

func (db *AraDatabase) DropDatabase(name string) (err error) {
	_db, err := db.client.Database(context.Background(), name)
	if err != nil {
		return fmt.Errorf("unable to connect to database [ERR: %s]", err)
	}

	err = _db.Remove(context.Background())
	if err != nil {
		return fmt.Errorf("unable to drop database [ERR: %s]", err)
	}

	return nil
}
