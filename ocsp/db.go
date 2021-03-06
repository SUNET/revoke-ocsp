package ocsp

import (
	"database/sql"
	"time"
)

type cert struct {
	Serial  int64     `json:"serial"`
	Revoked time.Time `json:"revoked"`
}

func getAll(db *sql.DB) (map[int64]*cert, error) {
	rows, err := db.Query("SELECT serial, revoked FROM revoked ORDER BY serial")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[int64]*cert)
	for rows.Next() {
		var c cert
		err = rows.Scan(&c.Serial, &c.Revoked)
		if err != nil {
			return nil, err
		}
		res[c.Serial] = &c
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func get(db *sql.DB, serial int64) (time.Time, error) {
	var revoked time.Time
	err := db.QueryRow("SELECT revoked FROM revoked WHERE serial = ?", serial).Scan(&revoked)
	return revoked, err
}

// Add a certificate to the database, overwriting a row with the same serial
// number if present.
func update(db *sql.DB, c *cert) error {
	// TODO: Prepare once
	stmt, err := db.Prepare("REPLACE INTO revoked VALUES (?, ?);")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(c.Serial, c.Revoked)
	if err != nil {
		return err
	}
	return nil
}

// Wipe database and replace it with cs
func initDB(db *sql.DB, certs []*cert) error {
	_, err := db.Exec(`
		DROP TABLE IF EXISTS revoked;
		CREATE TABLE "revoked" (
			"serial" INTEGER NOT NULL PRIMARY KEY,
			"revoked" DATE NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	for _, c := range certs {
		err = update(db, c)
		if err != nil {
			return err
		}
	}
	return nil
}
