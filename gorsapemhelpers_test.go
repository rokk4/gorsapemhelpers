package gorsapemhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Generates an RSA KeyPair for the test.
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privateKey, &privateKey.PublicKey
}

func TestRSAPemTools(t *testing.T) {

	// Create the key pair.
	privateKey, publicKey := generateRSAKeyPair()

	// Export the keys as PEM.
	privateKeyAsPEM := ExportRSAPrivateKeyAsPEM(privateKey)
	publicKeyAsPEM, _ := ExportRSAPublicKeyAsPEM(publicKey)

	// Import the keys from PEM.
	privateKeyFromPEM, _ := ParseRSAPrivateKeyFromPEM(privateKeyAsPEM)
	publicKeyFromPEM, _ := ParseRSAPublicKeyFromPEM(publicKeyAsPEM)

	// Export the imported keys as PEM.
	privateKeyParsedAsPEM := ExportRSAPrivateKeyAsPEM(privateKeyFromPEM)
	publicKeyParsedAsPEM, _ := ExportRSAPublicKeyAsPEM(publicKeyFromPEM)

	// Test if the exported/imported keys match the original keys.
	if privateKeyAsPEM != privateKeyParsedAsPEM || publicKeyAsPEM != publicKeyParsedAsPEM {
		t.Error("Export and Import did not result in same Keys")
	}
}
