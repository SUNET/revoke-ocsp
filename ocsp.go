package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ocsp"

	_ "github.com/mattn/go-sqlite3"
)

type requestError struct {
	msg string
}

func (e requestError) Error() string {
	return fmt.Sprintf("Bad request: %s", e.msg)
}

type errHandler func(w http.ResponseWriter, r *http.Request) error

func (fn errHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		if _, ok := err.(requestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readPEM(filename string) (*pem.Block, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("PEM parsing failure: %s", filename)
	}
	return block, nil
}

func readKey(filename string) (*ecdsa.PrivateKey, error) {
	pemBlock, err := readPEM(filename)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func readCert(filename string) (*x509.Certificate, error) {
	pemBlock, err := readPEM(filename)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

type cert struct {
	serial    int64
	revoked   bool
	revokedAt sql.NullTime
}

func readIndex(db *sql.DB) (map[int64]*cert, error) {
	rows, err := db.Query("SELECT serial, revoked, revoked_at FROM revoked ORDER BY serial")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[int64]*cert)
	for rows.Next() {
		c := cert{}
		err = rows.Scan(&c.serial, &c.revoked, &c.revokedAt)
		if err != nil {
			return nil, err
		}
		res[c.serial] = &c
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// Handle an OCSP request using standard library and golang.org/x/crypto/ocsp.
// Nonce extension [1] is NOT used. The responder's cert is included in the
// response. [2][3]
//
// [1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.1
// [2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
// [3]: https://github.com/golang/go/issues/22335
func makeOCSPHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return requestError{"Only POST requests are supported"}
		}

		index, err := readIndex(db)
		if err != nil {
			return err
		}

		// Read CA and responder certificate, responder key
		// TODO: Optimization: Only when needed.
		caCert, err := readCert(CA_CERT)
		if err != nil {
			return err
		}
		responderCert, err := readCert(RESPONDER_CERT)
		if err != nil {
			return err
		}
		responderKey, err := readKey(RESPONDER_KEY)
		if err != nil {
			return err
		}

		// Parse request
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return err
		}
		req, err := ocsp.ParseRequest(body)

		// Create response
		now := time.Now()
		tmpl := ocsp.Response{
			Certificate:  caCert,
			SerialNumber: req.SerialNumber,
			IssuerHash:   crypto.SHA1,
			ThisUpdate:   now,
			// NextUpdate:   now.Add(time.Hour), // TODO
		}

		serial := req.SerialNumber.Int64()
		if !req.SerialNumber.IsInt64() {
			return errors.New("Requested serial number is larger than 64 bits")
		}

		if c, found := index[serial]; !found {
			tmpl.Status = ocsp.Unknown
		} else if c.revoked {
			tmpl.Status = ocsp.Revoked
			if !c.revokedAt.Valid {
				return errors.New("No revocation date in database entry")
			}
			tmpl.RevokedAt = c.revokedAt.Time
			tmpl.RevocationReason = ocsp.Unspecified // TODO
		} else {
			tmpl.Status = ocsp.Good
		}

		// Sign response using responder certificate
		resp, err := ocsp.CreateResponse(caCert, responderCert, tmpl, responderKey)
		if err != nil {
			return err
		}

		// Write HTTP response
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
		w.Write(resp)
		return nil
	}
}

// Read JSON from rc, populate struct pointed to by data
func readJSON(rc io.ReadCloser, data interface{}) (interface{}, error) {
	jsonData, err := io.ReadAll(rc)
	if err != nil {
		return nil, requestError{"Bad body"}
	}

	err = json.Unmarshal(jsonData, data)
	if err != nil {
		return nil, requestError{"Bad body"}
	}

	return data, nil
}

// Add a certificate to the database, overwriting a row with the same serial
// number if present. If revokedAt is zero, the current time is used as
// revocation time.
func add(db *sql.DB, serial int, revoked bool, revokedAt time.Time) error {
	// TODO: Prepare once
	stmt, err := db.Prepare("REPLACE INTO revoked VALUES (?, ?, ?);")
	if err != nil {
		return err
	}
	defer stmt.Close()

	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	var revokedAtStr string
	if revoked {
		revokedAtStr = revokedAt.Format(time.RFC3339)
	}

	_, err = stmt.Exec(serial, revoked, revokedAtStr)
	if err != nil {
		return err
	}
	return nil
}

func makeAddHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return requestError{"Only POST requests are supported"}
		}

		body := struct {
			Serial    int
			Revoked   bool
			RevokedAt time.Time
		}{}
		_, err := readJSON(r.Body, &body)
		if err != nil {
			return err
		}

		add(db, body.Serial, body.Revoked, body.RevokedAt)
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

func main() {
	db, err := sql.Open("sqlite3", "dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	http.Handle("/ocsp", makeOCSPHandler(db))
	http.Handle("/add", makeAddHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
