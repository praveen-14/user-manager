package database

import (
	"user-manager/database/models"
	utils "user-manager/utils"
)

const (
	ErrDBNotConnected = utils.ConstError("database not connected")
	ErrConflict       = utils.ConstError("conflicts with already existing record")
	ErrNotFound       = utils.ConstError("not found")
	ErrBadParams      = utils.ConstError("parameters not identified")

	OrderAsc  Order = "ASC"
	OrderDesc Order = "DESC"

	DeletedYes DeletedStatus = "DeletedYes"
	DeletedNo  DeletedStatus = "DeletedNo"
)

var (
	// better if this map can be made constant
	SortFieldsMap SortFields = SortFields{
		UserSortFields: UserSortFields{
			Name: "name",
		},
	}
)

// This interface includes funtion defintions used during runtime and it excludes one-time operations like table creation and indexing
type (
	Database interface {
		Disconnect() error

		// ErrConflict is returned if user already exists
		AddUser(user models.User) error

		// all non-null values in updates struct will be overwritten
		UpdateUser(updates models.User, tagsToAdd, tagsToRemove []string) error

		// ErrNotFound is returned if not found
		GetUser(id string) (models.User, error)

		ReadUsers(req ReadUsersRequest) (ReadUsersResponse, error) // total is not returned. Total can be fetched from a different API
	}

	// base

	Order string

	ReadRequest struct {
		Skip        int
		Limit       int
		CreatedFrom int64
		CreatedTo   int64
		SortOrder   Order
		Tags        []string
	}

	ReadResponse[T any] struct {
		Channel <-chan T
	}

	SortFields struct {
		UserSortFields
	}

	// user

	UserSortField string
	DeletedStatus string

	ReadUsersRequest struct {
		ReadRequest
		SortField UserSortField
		Deleted   DeletedStatus
	}

	ReadUsersResponse struct {
		ReadResponse[*models.User]
	}

	UserSortFields struct {
		Name UserSortField
	}
)
