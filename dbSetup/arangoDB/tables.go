package main

import (
	"user-manager/database"

	ara "github.com/arangodb/go-driver"
)

// TableConfig describes a arangodb table setup
type TableConfig struct {
	Name           string
	WaitForSync    bool
	EdgeDef        []ara.EdgeDefinition
	CollectionType ara.CollectionType
}

var (
	_tables = []*TableConfig{
		{
			Name:           database.UsersColName,
			WaitForSync:    true,
			CollectionType: ara.CollectionType(2),
		},
	}
)
