package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
			return errors.New("Only POST requests are supported")
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

		// Sign response using CA certificate
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

func main() {
	db, err := sql.Open("sqlite3", "dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	http.Handle("/ocsp", makeOCSPHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
