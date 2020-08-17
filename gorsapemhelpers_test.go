package gorsapemhelpers

import (
	"testing"
)

func TestRSAPemTools(t *testing.T) {

	// Create the key pair.
	privateKey, publicKey := GenerateRSAKeyPair()

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
