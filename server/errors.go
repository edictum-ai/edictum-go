// Package server provides the Server SDK for HTTP-backed governance.
package server

import "fmt"

// Error is returned when the server responds with an error status code.
type Error struct {
	StatusCode int
	Detail     string
}

func (e *Error) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Detail)
}

// BundleVerificationError is returned when a bundle signature is invalid.
type BundleVerificationError struct {
	Message string
}

func (e *BundleVerificationError) Error() string {
	return fmt.Sprintf("bundle verification failed: %s", e.Message)
}
