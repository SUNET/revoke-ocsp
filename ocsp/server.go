package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ocsp"
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

// Handle an OCSP request using standard library and golang.org/x/crypto/ocsp.
// Nonce extension [1] is NOT used. The responder's cert is included in the
// response. [2][3]
//
// [1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.1
// [2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
// [3]: https://github.com/golang/go/issues/22335
func MakeOCSPHandler(db *sql.DB, caCert, responderCert *x509.Certificate, responderKey *ecdsa.PrivateKey) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return requestError{"Only POST requests are supported"}
		}

		index, err := readIndex(db)
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
		} else if c.Revoked.IsZero() {
			tmpl.Status = ocsp.Good
		} else {
			tmpl.Status = ocsp.Revoked
			tmpl.RevokedAt = c.Revoked
			tmpl.RevocationReason = ocsp.Unspecified // TODO
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

func MakeUpdateHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "PUT" {
			return requestError{"Only PUT requests are supported"}
		}

		var c cert
		_, err := readJSON(r.Body, &c)
		if err != nil {
			return err
		}

		update(db, &c)
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

func MakeInitHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "PUT" {
			return requestError{"Only PUT requests are supported"}
		}
		var certs []*cert
		_, err := readJSON(r.Body, &certs)
		if err != nil {
			return err
		}
		initDB(db, certs)
		return nil
	}
}

func MakeAllHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "GET" {
			return requestError{"Only GET requests are supported"}
		}

		index, err := readIndex(db)
		if err != nil {
			return err
		}

		res, err := json.Marshal(index)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(res)
		return nil
	}
}
