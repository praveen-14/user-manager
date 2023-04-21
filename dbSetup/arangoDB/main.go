package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"user-manager/config"
	"user-manager/database"

	ara "github.com/arangodb/go-driver"
)

var (
	force bool
	err   error
)

func main() {
	flag.BoolVar(&force, "force", false, "Drop all tables!?!?")
	flag.Parse()

	if force {
		var reallyForce string
		fmt.Printf("Are you sure you want to drop %q? (n|Y)\n", config.DBNAME)
		fmt.Scanln(&reallyForce)
		if reallyForce != "Y" {
			return
		}
	}

	db, err := database.New()

	if err != nil {
		log.Fatalf("could not connect to database [ERR: %s]", err.Error())
	}

	err = db.CreateDatabase(config.DBNAME)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate database name") {
			if force {
				log.Printf("dropping existing \"%s\" database!", config.DBNAME)
				err2 := db.DropDatabase(config.DBNAME)
				if err2 != nil {
					log.Fatalf("could not drop \"%s\" database!", config.DBNAME)
				}
			} else {
				log.Printf("database named \"%s\" already exists. Rerun with --force flag to drop and create a new one", config.DBNAME)
			}
		} else {
			log.Printf("could not create database [ERR: %s]", err.Error())
		}
	} else {
		log.Printf("created \"%s\" database!", config.DBNAME)
	}

	for _, table := range _tables {
		err = db.CreateCollection(config.DBNAME, table.Name,
			&ara.CreateCollectionOptions{
				WaitForSync: table.WaitForSync,
				Type:        table.CollectionType,
			})
		if err != nil {
			log.Printf("unable to create table in %q [ERR: %s]", config.DBNAME, err)
		}

		if _, hasKey := _indexes[table.Name]; hasKey {
			for _, opts := range _indexes[table.Name] {

				err = db.CreateIndex(table.Name, opts)
				if err != nil {
					log.Printf("could not create index \"%s\" [collection: %s] [ERR:%s] [%+v]",
						opts.Name,
						table.Name,
						err.Error(),
						opts,
					)
				} else {
					log.Printf("    created index  => \"%s\"\n",
						opts.Name,
					)
				}
			}
		}
	}
}
