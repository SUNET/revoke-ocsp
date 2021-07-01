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
			"revoked" DATE NOT NULL
		);

		INSERT INTO "revoked" VALUES
			(1, "0001-01-01T00:00:00Z"),
			(2, "0001-01-01T00:00:00Z"),
			(3, "2019-10-12T07:20:50Z"),
			(4, "2019-10-12T07:20:50Z");
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func getCert(serial int) (res cert) {
	row := db.QueryRow(fmt.Sprintf("SELECT * FROM revoked WHERE serial = %d", serial))
	err := row.Scan(&res.Serial, &res.Revoked)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func getCount() (res int) {
	row := db.QueryRow("SELECT count(*) FROM revoked")
	err := row.Scan(&res)
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
				"revoked": "0001-01-01T00:00:00Z"
			},
			"2": {
				"serial": 2,
				"revoked": "0001-01-01T00:00:00Z"
			},
			"3": {
				"serial": 3,
				"revoked": "2019-10-12T07:20:50Z"
			},
			"4": {
				"serial": 4,
				"revoked": "2019-10-12T07:20:50Z"
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
				"revoked": "0001-01-01T00:00:00Z"
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{5, zeroTime}, getCert(5))
	})

	t.Run("Add revoked", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 5,
				"revoked": "2020-01-01T00:00:00Z"
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{5, getTime("2020-01-01T00:00:00Z")}, getCert(5))
	})

	t.Run("Replace", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 4,
				"revoked": "0001-01-01T00:00:00Z"
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, cert{4, zeroTime}, getCert(4))
	})
}

func TestInit(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeInitHandler(db)).
			Put("/init").
			Body("[]").
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, 0, getCount())
	})

	t.Run("Not empty", func(t *testing.T) {
		setup()
		apitest.New().
			Handler(makeInitHandler(db)).
			Put("/init").
			Body(`[
				{
					"serial": 1,
					"revoked": "0001-01-01T00:00:00Z"
				},
				{
					"serial": 2,
					"revoked": "2020-01-01T00:00:00Z"
				}
			]`).
			Expect(t).
			Status(http.StatusOK).
			End()

		assert.Equal(t, 2, getCount())
		assert.Equal(t, cert{1, zeroTime}, getCert(1))
		assert.Equal(t, cert{2, getTime("2020-01-01T00:00:00Z")}, getCert(2))
	})
}
