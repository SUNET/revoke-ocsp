package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type cert struct {
	Serial    int64     `json:"serial"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at"`
}

func main() {
	db, err := sql.Open("sqlite3", "dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	http.Handle("/ocsp", makeOCSPHandler(db))
	http.Handle("/update", makeUpdateHandler(db))
	http.Handle("/init", makeInitHandler(db))
	http.Handle("/all", makeAllHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
