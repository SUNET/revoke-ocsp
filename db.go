package main

import (
	"database/sql"
	"time"
)

func readIndex(db *sql.DB) (map[int64]*cert, error) {
	rows, err := db.Query("SELECT serial, revoked, revoked_at FROM revoked ORDER BY serial")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[int64]*cert)
	for rows.Next() {
		c := struct {
			serial    int64
			revoked   bool
			revokedAt sql.NullTime
		}{}
		err = rows.Scan(&c.serial, &c.revoked, &c.revokedAt)
		if err != nil {
			return nil, err
		}
		var revokedAt time.Time
		if c.revokedAt.Valid {
			revokedAt = c.revokedAt.Time
		}
		res[c.serial] = &cert{c.serial, c.revoked, revokedAt}
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// Add a certificate to the database, overwriting a row with the same serial
// number if present. If c.revokedAt is zero, the current time is used as
// revocation time.
func update(db *sql.DB, c *cert) error {
	// TODO: Prepare once
	stmt, err := db.Prepare("REPLACE INTO revoked VALUES (?, ?, ?);")
	if err != nil {
		return err
	}
	defer stmt.Close()

	if c.RevokedAt.IsZero() {
		c.RevokedAt = time.Now().UTC()
	}
	var revokedAtStr string
	if c.Revoked {
		revokedAtStr = c.RevokedAt.Format(time.RFC3339)
	}

	_, err = stmt.Exec(c.Serial, c.Revoked, revokedAtStr)
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
			"revoked" BOOLEAN NOT NULL,
			"revoked_at" DATE
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
