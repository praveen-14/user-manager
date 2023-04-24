package main

import (
	"user-manager/database"

	ara "github.com/arangodb/go-driver"
)

var (
	_indexes = map[string][]*database.Index{
		"users": {
			{
				EnsurePersistentIndexOptions: &ara.EnsurePersistentIndexOptions{
					Name:   "unique",
					Unique: true,
				},
				Fields: []string{"id"},
			},
			{
				EnsurePersistentIndexOptions: &ara.EnsurePersistentIndexOptions{
					Name: "role",
				},
				Fields: []string{"role"},
			},
		},
	}
)
