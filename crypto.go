package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

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
