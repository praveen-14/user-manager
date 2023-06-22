package mongodb

import (
	"context"
	"fmt"
	"sync"

	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/database"
	"github.com/praveen-14/user-manager/database/models"
	"github.com/praveen-14/user-manager/services/logger"
	"github.com/praveen-14/user-manager/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	lock            = &sync.Mutex{}
	instance        *MongoDB
	channelCapacity = 100
)

const (
	UsersColName = "users"
)

type (
	MongoDB struct {
		Logger *logger.Service

		Client *mongo.Client
		DB     *mongo.Database
	}
)

func New() (*MongoDB, error) {
	lock.Lock()
	defer lock.Unlock()
	if instance == nil {
		instance = &MongoDB{
			Logger: logger.New("mongo", 0),
		}

		// Use the SetServerAPIOptions() method to set the Stable API version to 1
		serverAPI := options.ServerAPI(options.ServerAPIVersion1)

		opts := options.Client().ApplyURI(fmt.Sprintf(`mongodb://%s:%s@%s:%d`, config.DBUSER, config.DBPASS, config.DBHOST, config.DBPORT)).SetServerAPIOptions(serverAPI)

		// Create a new client and connect to the server
		client, err := mongo.Connect(context.TODO(), opts)
		if err != nil {
			return nil, err
		}
		instance.Client = client
		instance.DB = client.Database(config.DBNAME)
	}
	return instance, nil
}

func (db *MongoDB) Disconnect() error {
	return db.Client.Disconnect(context.TODO())
}

// CRUD Users

func (db *MongoDB) AddUser(user models.User) error {
	coll := db.DB.Collection(UsersColName)
	_, err := coll.InsertOne(context.TODO(), encode(user))
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("adding user failed, id = %s [ERR=%s]", *user.ID, err))
		return database.ErrConflict
	}
	return nil
}

func (db *MongoDB) UpdateUser(updates models.User, tagsToAdd, tagsToRemove []string) error {
	coll := db.DB.Collection(UsersColName)
	filter := bson.M{"_id": updates.ID}
	update := encode(updates)
	full_update := map[string]any{}
	full_update["$addToSet"] = map[string]any{"tags": map[string]any{"$each": tagsToAdd}}
	full_update["$pull"] = map[string]any{"list": map[string]any{"$in": tagsToRemove}}
	full_update["$set"] = update
	_, err := coll.UpdateOne(context.TODO(), filter, full_update)
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("updating user failed, id = %s [ERR=%s]", *updates.ID, err))
		return database.ErrBadParams
	}
	return nil
}

func (db *MongoDB) GetUser(id string) (user models.User, err error) {
	coll := db.DB.Collection(UsersColName)
	filter := bson.M{"_id": id}
	data, err := coll.FindOne(context.TODO(), filter).DecodeBytes()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			db.Logger.Print("INFO", fmt.Sprintf("user does not exist, id = %s", id))
			return user, database.ErrNotFound
		}
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed, id = %s [ERR=%s]", id, err))
		return user, database.ErrUnidentified
	}
	m := make(map[string]any)
	err = bson.Unmarshal(data, &m)
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed (unmarshalling), id = %s [ERR=%s]", id, err))
		return user, database.ErrUnidentified
	}
	decode(m, &user)
	return user, nil
}

func (db *MongoDB) GetUserByEmail(email string) (user models.User, err error) {
	coll := db.DB.Collection(UsersColName)
	filter := bson.M{"email": email}
	data, err := coll.FindOne(context.TODO(), filter).DecodeBytes()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			db.Logger.Print("INFO", fmt.Sprintf("user does not exist, email = %s", email))
			return user, database.ErrNotFound
		}
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed, email = %s [ERR=%s]", email, err))
		return user, database.ErrUnidentified
	}
	m := make(map[string]any)
	err = bson.Unmarshal(data, &m)
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed (unmarshalling), email = %s [ERR=%s]", email, err))
		return user, database.ErrUnidentified
	}
	decode(m, &user)
	return user, nil
}

func (db *MongoDB) GetUsers(ids []string) (out <-chan *models.User, err error) {
	filters := []bson.M{}
	for _, id := range ids {
		filters = append(filters, bson.M{"_id": id})
	}
	filter := bson.M{"$or": filters}

	dataChan := make(chan *models.User, channelCapacity)

	go func() {
		defer close(dataChan)

		coll := db.DB.Collection(UsersColName)
		cur, err := coll.Find(context.TODO(), filter)
		if err != nil {
			db.Logger.Print("FAIL", fmt.Sprintf("getting users failed, ids = %+v [ERR=%s]", ids, err))
			return
		}

		for cur.Next(context.TODO()) {
			user := &models.User{}
			m := make(map[string]any)
			err := bson.Unmarshal(cur.Current, &m)
			if err != nil {
				db.Logger.Fatalf("reading users [ERR: %s]", err)
			}
			decode(m, user)
			dataChan <- user
		}

	}()

	return dataChan, nil
}

func (db *MongoDB) ReadUsers(req database.ReadUsersRequest) (res database.ReadUsersResponse, err error) {

	dataChan := make(chan *models.User, channelCapacity)

	opts := options.Find()
	if req.SortField != "" && req.SortOrder != "" {
		mongoSortOrder := 1
		if req.SortOrder == database.OrderDesc {
			mongoSortOrder = 0
		}
		opts.SetSort(bson.M{string(req.SortField): mongoSortOrder})
	}
	deletedFilter := genDeletedQuery(req.Deleted)
	rolesFilter := genRolesQuery(req.Roles)
	readFilter, err := genReadQuery(opts, req.ReadRequest)

	if err != nil {
		db.Logger.Print("FAIL", "failed to generate query, req = %+v, err = %s", req, err)
		return res, err
	}

	filtersArr := []bson.M{}
	if len(deletedFilter) > 0 {
		filtersArr = append(filtersArr, deletedFilter)
	}
	if len(rolesFilter) > 0 {
		filtersArr = append(filtersArr, rolesFilter)
	}
	if len(readFilter) > 0 {
		filtersArr = append(filtersArr, readFilter)
	}

	var filter any
	if len(filtersArr) > 0 {
		filter = bson.M{"$and": filtersArr}
	}

	// fmt.Printf("%+v\n\n", filter)
	// fmt.Printf("%+v\n\n", opts)

	go func() {
		defer close(dataChan)

		coll := db.DB.Collection(UsersColName)
		cur, err := coll.Find(context.TODO(), filter, opts)
		if err != nil {
			db.Logger.Print("FAIL", "reading users failed, req = %+v, err = %s", req, err)
			return
		}

		for cur.Next(context.TODO()) {
			user := &models.User{}
			m := make(map[string]any)
			err := bson.Unmarshal(cur.Current, &m)
			if err != nil {
				db.Logger.Fatalf("reading users [ERR: %s]", err)
			}
			decode(m, user)
			dataChan <- user
		}

	}()

	res.ReadResponse.Channel = dataChan

	return res, nil
}

// converts struct to map (id is renamed to _key)
func encode(obj any) map[string]interface{} {
	dict := utils.ToDict(obj)
	dict["_id"] = dict["id"]
	delete(dict, "id")
	return dict
}

// converts map to given type (_key is renamed to id)
func decode[T any](_obj map[string]interface{}, objPointer *T) {
	_obj["id"] = _obj["_id"]
	delete(_obj, "_id")
	utils.ToObj(_obj, objPointer)
}

func genReadQuery(opts *options.FindOptions, req database.ReadRequest) (filters bson.M, err error) {
	filtersArr := []bson.M{}

	if req.CreatedFrom != 0 {
		filtersArr = append(filtersArr, bson.M{"created_at": bson.M{"$gt": req.CreatedFrom}})
	}

	if req.CreatedTo != 0 {
		filtersArr = append(filtersArr, bson.M{"created_at": bson.M{"$lt": req.CreatedFrom}})
	}

	if len(req.Tags) > 0 {
		tagsArr := []bson.M{}
		for t := range req.Tags {
			tagsArr = append(tagsArr, bson.M{"tags": t})
		}
		filtersArr = append(filtersArr, bson.M{"$and": filtersArr})
	}

	if len(filtersArr) > 0 {
		filters = bson.M{"$and": filtersArr}
	}

	if req.Skip < 0 || req.Limit < 0 {
		return filters, database.ErrBadParams
	}
	opts.SetSkip(int64(req.Skip)).SetLimit(int64(req.Limit))

	return filters, nil
}

func genDeletedQuery(deletedStatus database.DeletedStatus) bson.M {
	if deletedStatus == database.DeletedYes {
		return bson.M{"deleted": true}
	} else if deletedStatus == database.DeletedNo {
		return bson.M{"deleted": false}
	}
	return bson.M{}
}

func genRolesQuery(roles []string) bson.M {
	if len(roles) > 0 {
		filtersArr := []bson.M{}
		for _, r := range roles {
			filtersArr = append(filtersArr, bson.M{"role": r})
		}
		return bson.M{"$or": filtersArr}
	}
	return bson.M{}
}
