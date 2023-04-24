package mongodb

import (
	"context"
	"fmt"
	"sync"
	"user-manager/config"
	"user-manager/database"
	"user-manager/database/models"
	"user-manager/services/logger"
	"user-manager/utils"

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
	filter := bson.D{{Key: "_id", Value: updates.ID}}
	update := encode(updates)
	update["$addToSet"] = map[string]any{"tags": map[string]any{"$each": tagsToAdd}}
	update["$pull"] = map[string]any{"list": map[string]any{"$in": tagsToRemove}}
	_, err := coll.UpdateOne(context.TODO(), filter, map[string]any{"$set": update})
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("updating user failed, id = %s [ERR=%s]", *updates.ID, err))
		return database.ErrBadParams
	}
	return nil
}

func (db *MongoDB) GetUser(id string) (user models.User, err error) {
	coll := db.DB.Collection(UsersColName)
	filter := bson.D{{Key: "_id", Value: id}}
	data, err := coll.FindOne(context.TODO(), filter).DecodeBytes()
	if err != nil {
		db.Logger.Print("FAIL", fmt.Sprintf("getting user failed, id = %s [ERR=%s]", *user.ID, err))
		return user, database.ErrConflict
	}
	m := make(map[string]any)
	err = bson.Unmarshal(data, &m)
	if err != nil {
		panic(fmt.Sprintf("getting user failed (unmarshalling), id = %s [ERR=%s]", *user.ID, err))
	}
	decode(m, &user)
	return user, nil
}

func (db *MongoDB) ReadUsers(req database.ReadUsersRequest) (res database.ReadUsersResponse, err error) {

	dataChan := make(chan *models.User, channelCapacity)

	opts := options.Find()
	if req.SortField != "" && req.SortOrder != "" {
		mongoSortOrder := 1
		if req.SortOrder == database.OrderDesc {
			mongoSortOrder = 0
		}
		opts.SetSort(bson.D{{Key: string(req.SortField), Value: mongoSortOrder}})
	}
	deletedFilter := genDeletedQuery(req.Deleted)
	readFilter, err := genReadQuery(opts, req.ReadRequest)

	if err != nil {
		db.Logger.Print("FAIL", "failed to generate query, req = %+v, err = %s", req, err)
		return res, err
	}

	filters := bson.D{{Key: "$and", Value: []bson.D{deletedFilter, readFilter}}}

	go func() {
		defer close(dataChan)

		coll := db.DB.Collection(UsersColName)
		cur, err := coll.Find(context.TODO(), filters, opts)
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

func genReadQuery(opts *options.FindOptions, req database.ReadRequest) (filters bson.D, err error) {
	filtersArr := []bson.D{}

	if req.CreatedFrom != 0 {
		filtersArr = append(filtersArr, bson.D{{Key: "created_at", Value: bson.D{{Key: "$gt", Value: req.CreatedFrom}}}})
	}

	if req.CreatedTo != 0 {
		filtersArr = append(filtersArr, bson.D{{Key: "created_at", Value: bson.D{{Key: "$lt", Value: req.CreatedFrom}}}})
	}

	if len(req.Tags) > 0 {
		tagsArr := []bson.D{}
		for t := range req.Tags {
			tagsArr = append(tagsArr, bson.D{{Key: "tags", Value: t}})
		}
		filtersArr = append(filtersArr, bson.D{{Key: "$and", Value: filtersArr}})
	}

	filters = bson.D{{Key: "$and", Value: filtersArr}}

	if req.Skip < 0 || req.Limit < 0 {
		return nil, database.ErrBadParams
	}
	opts.SetSkip(int64(req.Skip)).SetLimit(int64(req.Limit))

	return filters, nil
}

func genDeletedQuery(deletedStatus database.DeletedStatus) bson.D {
	if deletedStatus == database.DeletedYes {
		return bson.D{{Key: "deleted", Value: true}}
	} else if deletedStatus == database.DeletedNo {
		return bson.D{{Key: "deleted", Value: false}}
	}
	return bson.D{}
}
