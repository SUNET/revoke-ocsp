package ocsp

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
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

func run(name string, arg ...string) string {
	out, err := exec.Command(name, arg...).Output()
	if err != nil {
		log.Fatal(string(err.(*exec.ExitError).Stderr))
	}
	return string(out)
}

func root(file string) string {
	return filepath.Join("..", file)
}

func loadEnv() {
	godotenv.Load(root("default.env"))
	godotenv.Overload(root("custom.env"))
}

func assertEnv(required ...string) {
	for _, v := range required {
		if _, ok := os.LookupEnv(v); !ok {
			log.Fatal(fmt.Errorf("Environment variable %s not defined", v))
		}
	}
}

// Tests

func TestMain(m *testing.M) {
	var REQUIRED_ENV_VARS = []string{
		"CA_CERT",
		"RESPONDER_CERT",
		"RESPONDER_KEY",
		"PORT",
	}
	loadEnv()
	assertEnv(REQUIRED_ENV_VARS...)
	assertEnv("TEST_CLIENT_CERT")

	var err error
	db, err = sql.Open("sqlite3", ":memory:") // In-memory database
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	os.Exit(m.Run())
}

func TestOCSP(t *testing.T) {
	setup()

	caCert, err := ReadCert(root(os.Getenv("CA_CERT")))
	if err != nil {
		log.Fatal(err)
	}
	responderCert, err := ReadCert(root(os.Getenv("RESPONDER_CERT")))
	if err != nil {
		log.Fatal(err)
	}
	responderKey, err := ReadKey(root(os.Getenv("RESPONDER_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/ocsp", MakeOCSPHandler(db, caCert, responderCert, responderKey))

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", os.Getenv("PORT")))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Fatal(http.Serve(l, nil))
	}()

	t.Run("#1: Good (zero value revocation time)", func(t *testing.T) {
		status := strings.Split(
			run("openssl", "ocsp",
				"-CAfile", root(os.Getenv("CA_CERT")),
				"-issuer", root(os.Getenv("CA_CERT")),
				"-cert", root(os.Getenv("TEST_CLIENT_CERT")),
				"-url", fmt.Sprintf("http://localhost:%s/ocsp", os.Getenv("PORT"))),
			"\n")[0]
		assert.Equal(t, root(os.Getenv("TEST_CLIENT_CERT"))+": good", status)
	})

	t.Run("Revoke #1 using /update", func(t *testing.T) {
		apitest.New().
			Handler(MakeUpdateHandler(db)).
			Put("/update").
			Body(`{
				"serial": 1,
				"revoked": "2020-01-01T00:00:00Z"
			}`).
			Expect(t).
			Status(http.StatusOK).
			End()
	})

	t.Run("#1: Revoked", func(t *testing.T) {
		status := strings.Split(
			run("openssl", "ocsp",
				"-CAfile", root(os.Getenv("CA_CERT")),
				"-issuer", root(os.Getenv("CA_CERT")),
				"-cert", root(os.Getenv("TEST_CLIENT_CERT")),
				"-url", fmt.Sprintf("http://localhost:%s/ocsp", os.Getenv("PORT"))),
			"\n")[0]
		assert.Equal(t, root(os.Getenv("TEST_CLIENT_CERT"))+": revoked", status)
	})

	t.Run("#1: Unknown serial number", func(t *testing.T) {
		// NOTE: This status might be changed from "good" to "unknown" in the future
		_, err := db.Exec(`DELETE FROM revoked WHERE serial = 1`)
		if err != nil {
			log.Fatal(err)
		}

		status := strings.Split(
			run("openssl", "ocsp",
				"-CAfile", root(os.Getenv("CA_CERT")),
				"-issuer", root(os.Getenv("CA_CERT")),
				"-cert", root(os.Getenv("TEST_CLIENT_CERT")),
				"-url", fmt.Sprintf("http://localhost:%s/ocsp", os.Getenv("PORT"))),
			"\n")[0]
		assert.Equal(t, root(os.Getenv("TEST_CLIENT_CERT"))+": good", status)
	})
}

func TestAll(t *testing.T) {
	setup()
	apitest.New().
		Handler(MakeAllHandler(db)).
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
			Handler(MakeUpdateHandler(db)).
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
			Handler(MakeUpdateHandler(db)).
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
			Handler(MakeUpdateHandler(db)).
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
			Handler(MakeInitHandler(db)).
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
			Handler(MakeInitHandler(db)).
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
