// Package server provides the Server SDK for connecting edictum-go agents
// to edictum-console for remote rule management, audit delivery, session
// state, approval workflows, and hot-reload via SSE.
//
// Core components:
//   - Client: HTTP client with TLS enforcement, retries, and auth
//   - Backend: session.StorageBackend over HTTP
//   - AuditSink: batching audit.Sink over HTTP
//   - SSEWatcher: SSE-based rule hot-reload
//   - ApprovalBackend: approval.Backend over HTTP
//   - VerifyBundleSignature: Ed25519 bundle verification
package server
