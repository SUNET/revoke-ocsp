package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

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
