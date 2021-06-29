package main

import (
	"database/sql"
	"time"
)

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

// Add a certificate to the database, overwriting a row with the same serial
// number if present. If revokedAt is zero, the current time is used as
// revocation time.
func update(db *sql.DB, serial int64, revoked bool, revokedAt time.Time) error {
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
