package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	. "github.com/ernstwi/revoke-ocsp/ocsp"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

var REQUIRED_ENV_VARS = []string{
	"CA_CERT",
	"RESPONDER_CERT",
	"RESPONDER_KEY",
	"PORT",
	"DB",
}

func loadEnv() {
	godotenv.Load("default.env")
	godotenv.Overload("custom.env")
}

func assertEnv(required ...string) {
	for _, v := range required {
		if _, ok := os.LookupEnv(v); !ok {
			log.Fatal(fmt.Errorf("Environment variable %s not defined", v))
		}
	}
}

func main() {
	loadEnv()
	assertEnv(REQUIRED_ENV_VARS...)

	db, err := sql.Open("sqlite3", os.Getenv("DB"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	caCert, err := ReadCert(os.Getenv("CA_CERT"))
	if err != nil {
		log.Fatal(err)
	}
	responderCert, err := ReadCert(os.Getenv("RESPONDER_CERT"))
	if err != nil {
		log.Fatal(err)
	}
	responderKey, err := ReadKey(os.Getenv("RESPONDER_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/ocsp", MakeOCSPHandler(db, caCert, responderCert, responderKey))

	http.Handle("/update", MakeUpdateHandler(db))
	http.Handle("/init", MakeInitHandler(db))
	http.Handle("/all", MakeAllHandler(db))

	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))
}
