package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	. "github.com/ernstwi/ocsp-responder/ocsp"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	caCert, err := ReadCert(CA_CERT)
	if err != nil {
		log.Fatal(err)
	}
	responderCert, err := ReadCert(RESPONDER_CERT)
	if err != nil {
		log.Fatal(err)
	}
	responderKey, err := ReadKey(RESPONDER_KEY)
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/ocsp", MakeOCSPHandler(db, caCert, responderCert, responderKey))

	http.Handle("/update", MakeUpdateHandler(db))
	http.Handle("/init", MakeInitHandler(db))
	http.Handle("/all", MakeAllHandler(db))

	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", PORT), nil))
}
