// TEST DATA FIXTURE - VULNERABLE GO PATTERNS
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
	"unsafe"
)

func queryData(db *sql.DB, input string) {
	// SQL Injection via Sprintf (ENT-GO-001)
	query := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", input)
	db.Query(query)
}

func setupClient() {
	// Insecure TLS (ENT-GO-002)
	_ = &tls.Config{
		InsecureSkipVerify: true,
	}
}

func runShell(cmd string) {
	// Dangerous command execution (ENT-GO-003)
	_ = exec.Command("sh", "-c", cmd)
}

func inspectMemory(val int64) float64 {
	// Unsafe Pointer bypass (ENT-GO-004)
	ptr := unsafe.Pointer(&val)
	return *(*float64)(ptr)
}
