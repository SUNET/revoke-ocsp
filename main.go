package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type cert struct {
	serial    int64
	revoked   bool
	revokedAt time.Time
}

func main() {
	db, err := sql.Open("sqlite3", "dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	http.Handle("/ocsp", makeOCSPHandler(db))
	http.Handle("/update", makeUpdateHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
