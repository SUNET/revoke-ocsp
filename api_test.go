package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/steinfletcher/apitest"
)

var db *sql.DB

func TestMain(m *testing.M) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:") // In-memory database
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE "revoked" (
			"serial" INTEGER NOT NULL PRIMARY KEY,
			"revoked" BOOLEAN NOT NULL,
			"revoked_at" DATE
		);

		INSERT INTO "revoked" VALUES
			(1, 0, NULL),
			(2, 0, NULL),
			(3, 1, "2019-10-12T07:20:50Z"),
			(4, 1, "2019-10-12T07:20:50Z");
	`)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func TestAll(t *testing.T) {
	apitest.New().
		Handler(makeAllHandler(db)).
		Get("/all").
		Expect(t).
		Status(http.StatusOK).
		Body(`{
			"1": {
				"serial": 1,
				"revoked": false,
				"revoked_at": "0001-01-01T00:00:00Z"
			},
			"2": {
				"serial": 2,
				"revoked": false,
				"revoked_at": "0001-01-01T00:00:00Z"
			},
			"3": {
				"serial": 3,
				"revoked": true,
				"revoked_at": "2019-10-12T07:20:50Z"
			},
			"4": {
				"serial": 4,
				"revoked": true,
				"revoked_at": "2019-10-12T07:20:50Z"
			}
		}`).
		End()
}
