package main

import (
	"flag"
	"log"

	"github.com/praveen-14/user-manager/config"
	"github.com/praveen-14/user-manager/database/mongodb"
	"github.com/praveen-14/user-manager/server"
)

func init() {
	flag.StringVar(&config.EMAIL_TEMPLATE_DIR, "templatedir", config.EMAIL_TEMPLATE_DIR, "Directory containing the email templates")
	flag.Parse()
}

func main() {
	db, err := mongodb.New()
	if err != nil {
		log.Fatalf("connecting to database [ERR: %s]", err)
	}

	server, err := server.New(db)
	if err != nil {
		log.Fatal("failed to start server", err)
	}

	server.Run()
}
