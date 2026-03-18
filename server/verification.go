package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// VerifyBundleSignature verifies an Ed25519 signature over raw YAML bytes.
// Returns a BundleVerificationError if the signature is invalid or inputs
// are malformed.
func VerifyBundleSignature(yamlBytes []byte, signatureB64, publicKeyHex string) error {
	if signatureB64 == "" {
		return &BundleVerificationError{Message: "signature is empty"}
	}
	if publicKeyHex == "" {
		return &BundleVerificationError{Message: "public key is empty"}
	}

	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return &BundleVerificationError{
			Message: fmt.Sprintf("invalid public key hex encoding: %v", err),
		}
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return &BundleVerificationError{
			Message: fmt.Sprintf("public key wrong size: got %d bytes, want %d", len(pubKeyBytes), ed25519.PublicKeySize),
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return &BundleVerificationError{
			Message: fmt.Sprintf("invalid signature base64 encoding: %v", err),
		}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return &BundleVerificationError{
			Message: fmt.Sprintf("signature wrong size: got %d bytes, want %d", len(sigBytes), ed25519.SignatureSize),
		}
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, yamlBytes, sigBytes) {
		return &BundleVerificationError{
			Message: "bundle signature verification failed -- the bundle may have been tampered with",
		}
	}
	return nil
}
