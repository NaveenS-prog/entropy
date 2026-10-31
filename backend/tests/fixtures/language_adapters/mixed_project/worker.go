package main

import (
	"crypto/tls"
)

func runWorker() {
	_ = &tls.Config{InsecureSkipVerify: true}
}
