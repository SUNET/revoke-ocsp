package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func check(err error, w *http.ResponseWriter) {
	if err != nil {
		http.Error(*w, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Only POST requests are supported", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		check(err, &w)

		// TODO: Later replace wd with an empty string to use OS default
		// directory for temporary files, and delete the working directory when
		// done.
		workDir, err := ioutil.TempDir("wd", "")
		check(err, &w)

		reqFileName := filepath.Join(workDir, "req.der")
		respFileName := filepath.Join(workDir, "resp.der")

		// Write certificate request
		reqFile, err := os.Create(reqFileName)
		check(err, &w)
		_, err = reqFile.Write(body)
		check(err, &w)
		reqFile.Close()

		// Create certificate response
		err = exec.Command("openssl", "ocsp",
			"-index", "data/index.txt",
			"-CAfile", "data/get.eduroam.se.pem",
			"-rsigner", "data/get.eduroam.se.pem",
			"-rkey", "data/get.eduroam.se.key.pem",
			"-CA", "data/get.eduroam.se.pem",
			"-reqin", reqFileName,
			"-respout", respFileName).Run()
		check(err, &w)

		// Read certificate response
		resp, err := os.ReadFile(respFileName)
		check(err, &w)

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
		w.Write(resp)
	})
	log.Fatal(http.ListenAndServe("localhost:8889", nil))
}
