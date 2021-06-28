package main

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := fn(w, r); err != nil {
		if _, ok := err.(requestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println(err) // TODO: Remove
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

func register(m map[int64]bool, serial int64, status string) (map[int64]bool, error) {
	switch status {
	case "V":
		m[serial] = true
	case "R":
		m[serial] = false
	default:
		return m, fmt.Errorf("Unrecognized status field in index file: %s", status)
	}
	return m, nil
}

// Handle an OCSP request using standard library and golang.org/x/crypto/ocsp.
// Nonce extension [1] is NOT used. The responder's cert is included in the
// response. [2][3]
//
// [1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.1
// [2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
// [3]: https://github.com/golang/go/issues/22335
func makeOCSPHandler() errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return errors.New("Only POST requests are supported")
		}

		// Read index.txt
		//
		// TODO: Index file is for a single CA. If we decide to use go crypto we
		// will probably replace the OpenSSL index format entirely.
		// TODO: Optimization: Only when needed.
		index := make(map[int64]bool) // TODO: Do we need big.Int?
		file, err := os.Open("data/index.txt")
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var status string
			var serial int64
			row := strings.Split(scanner.Text(), "\t")
			status = row[0]
			serial, err = strconv.ParseInt(row[3], 10, 64)
			if err != nil {
				return err
			}
			_, err = register(index, serial, status)
			if err != nil {
				return err
			}
		}

		// Read CA certificate, key
		// TODO: Optimization: Only when needed.
		pemBlock, err := readPEM("data/get.eduroam.se.pem")
		if err != nil {
			return err
		}
		caCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return err
		}
		pemBlock, err = readPEM("data/get.eduroam.se.key.pem")
		if err != nil {
			return err
		}
		caKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
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

		if s, found := index[serial]; !found {
			tmpl.Status = ocsp.Unknown
		} else if s {
			tmpl.Status = ocsp.Good
		} else {
			tmpl.Status = ocsp.Revoked
			tmpl.RevokedAt = now
			tmpl.RevocationReason = ocsp.Unspecified // TODO
		}

		// Sign response using CA certificate
		resp, err := ocsp.CreateResponse(caCert, caCert, tmpl, caKey)
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
	http.Handle("/ocsp", makeOCSPHandler())
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
