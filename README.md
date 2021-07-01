## Private API specification

### `/ocsp`

- Method: POST

Responds to POST OSCP requests according to RFC 6960.

### `/update`

- Method: PUT
- Body: JSON
    - `serial`: integer
    - `revoked`: boolean
    - `revoked_at`: RFC 3339 string, with "0001-01-01T00:00:00Z" signifying null

Add a certificate to the OCSP database, overwriting a row with the same serial number if present. If `revoked_at` is "0001-01-01T00:00:00Z" (RFC 3339 format of date's zero value in Go), the current time is used as revocation time.

### `/init`

- Method: PUT
- Body: JSON
    - Array of objects with properties
        - `serial`: integer
        - `revoked`: boolean
        - `revoked_at`: RFC 3339 string, with "0001-01-01T00:00:00Z" signifying null

Wipe the OCSP database and initialize it with the given data.

### `/all`

- Method: GET

Responds with map of all OCSP database entries.
