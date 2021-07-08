# ocsp-responder

## Configuration

The following environment variables are required:

```
CA_CERT
RESPONDER_CERT
RESPONDER_KEY
PORT
```

For testing an additional variable `TEST_CLIENT_CERT` should point to a certificate signed by `CA_CERT` with serial number 1.

You can either edit `default.env`, or use a new file `custom.env` which will override `default.env`.

## Initialization

To initialize the revocation database, do

```
$ sqlite3 dev.sqlite < init.sql
```

## Private API specification

### `/ocsp`

- Method: POST

Responds to POST OSCP requests according to RFC 6960.

### `/update`

- Method: PUT
- Body: JSON
    - `serial`: integer
    - `revoked`: RFC 3339 string, with "0001-01-01T00:00:00Z" signifying null

Add a certificate to the OCSP database, overwriting a row with the same serial number if present.

### `/init`

- Method: PUT
- Body: JSON
    - Array of objects with properties
        - `serial`: integer
        - `revoked`: RFC 3339 string, with "0001-01-01T00:00:00Z" signifying null

Wipe the OCSP database and initialize it with the given data.

### `/all`

- Method: GET

Responds with map of all OCSP database entries.
