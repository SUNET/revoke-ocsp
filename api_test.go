package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
)

var db *sql.DB
var zeroTime time.Time

// Helpers

func setup() {
	_, err := db.Exec(`
		DROP TABLE IF EXISTS "revoked";

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
}

func getCert(serial int) (res cert) {
	row := db.QueryRow(fmt.Sprintf("SELECT * FROM revoked WHERE serial = %d", serial))
	err := row.Scan(&res.Serial, &res.Revoked, &res.RevokedAt)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func getTime(s string) (res time.Time) {
	res, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// Tests

func TestMain(m *testing.M) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:") // In-memory database
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	os.Exit(m.Run())
}

func TestAll(t *testing.T) {
	setup()
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

func TestUpdate(t *testing.T) {
	t.Run("Add non revoked", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 5,
				"revoked": false
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{5, false, zeroTime}, getCert(5))
	})

	t.Run("Add revoked (no date)", func(t *testing.T) {
		setup()
		a := time.Now().UTC().Truncate(time.Second)
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 5,
				"revoked": true
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()
		b := time.Now().UTC().Truncate(time.Second)
		c := getCert(5).RevokedAt
		if !(c.Equal(a) || c.After(a)) || !(c.Equal(b) || c.Before(b)) {
			t.Errorf("%v is not between %v and %v", c, a, b)
		}
	})

	t.Run("Add revoked (with date)", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 5,
				"revoked": true,
				"revoked_at": "2020-01-01T00:00:00Z"
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{5, true, getTime("2020-01-01T00:00:00Z")}, getCert(5))
	})

	t.Run("Replace", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 4,
				"revoked": false
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{4, false, zeroTime}, getCert(4))
	})
}
