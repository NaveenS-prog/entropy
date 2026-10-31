// TEST DATA FIXTURE - CLEAN GO PATTERNS
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
)

func queryDataSafe(db *sql.DB, input string) (*sql.Rows, error) {
	// Parameterized SQL query
	return db.Query("SELECT * FROM items WHERE name = ?", input)
}

func setupClientSafe() *tls.Config {
	// Secure TLS config with certificate validation
	return &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}
}

func formatGreeting(name string) string {
	return fmt.Sprintf("Hello, %s", name)
}
