package fixtures

import (
	"crypto/rand"
	"crypto/rsa"
)

// legacyBits is a package-level const. OpenGrep does NOT resolve these in Go,
// so the wrapper below is reached through a direct literal instead. See
// test_taint_scanner.py::test_module_level_constants_are_a_known_boundary.
const legacyBits = 1024

func buildKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// LegacyKey passes a literal through the wrapper — this is resolved.
func LegacyKey() (*rsa.PrivateKey, error) {
	return buildKey(1024)
}

// ConstKey passes a package const — this is NOT resolved.
func ConstKey() (*rsa.PrivateKey, error) {
	return buildKey(legacyBits)
}
