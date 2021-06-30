package main

import (
	"database/sql"
	"fmt"
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

	caCert, err := readCert(CA_CERT)
	if err != nil {
		log.Fatal(err)
	}
	responderCert, err := readCert(RESPONDER_CERT)
	if err != nil {
		log.Fatal(err)
	}
	responderKey, err := readKey(RESPONDER_KEY)
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/ocsp", makeOCSPHandler(db, caCert, responderCert, responderKey))

	http.Handle("/update", makeUpdateHandler(db))
	http.Handle("/init", makeInitHandler(db))
	http.Handle("/all", makeAllHandler(db))

	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", PORT), nil))
}
