package spake2

import (
	"github.com/jtejido/spake2/internal/suite"
	"github.com/stretchr/testify/assert"
	"testing"
)

var mhfScrypt = Scrypt(16, 1, 1)

type Suite func(mhf suite.MHF) suite.CipherSuite

var testSuites = []Suite{
	P256Sha256HkdfHmac,
	P384Sha256HkdfHmac,
	P256Sha512HkdfHmac,
	P384Sha512HkdfHmac,
	Ed25519Sha256HkdfHmac,
	Ed448Sha512HkdfHmac,
}

// SPAKE2
func testSPAKE2Scrypt(t *testing.T, testSuite Suite, mhf suite.MHF) {
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("this_is_a_test_password")
	salt := []byte("NaCl")
	aad := []byte("")

	// Creates a SPAKE2 instance
	s := New(suite)

	verifier, err := s.ComputeVerifier(password, salt)
	if !assert.NoError(t, err) {
		return
	}

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartA(clientIdentity, serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}

	stateB, messageB, err := s.StartB(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the confirmation message from each other.
	confirmationA := sharedSecretA.Confirmation()
	confirmationB := sharedSecretB.Confirmation()

	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
}

func testSPAKE2WithWrongPasswordScrypt(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("this_is_a_test_password")
	salt := []byte("NaCl")
	aad := []byte("")

	// Creates a SPAKE2 instance
	s := New(suite)
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartA(clientIdentity, serverIdentity, []byte("a_wrong_password"), salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartB(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.Confirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func testSPAKE2WithWrongClientIdentityScrypt(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("this_is_a_test_password")
	salt := []byte("NaCl")
	aad := []byte("")
	// Creates a SPAKE2 instance
	s := New(suite)
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartA([]byte("another_client"), serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartB(clientIdentity, serverIdentity, verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// B verifies the confirmation message from A - and fails.
	confirmationA := sharedSecretA.Confirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func testSPAKE2WithWrongServerIdentityScrypt(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("this_is_a_test_password")
	salt := []byte("NaCl")
	aad := []byte{}

	// Creates a SPAKE2 instance
	s := New(suite)
	verifier, err := s.ComputeVerifier(password, salt)

	// Creates a SPAKE2 client and a SPAKE2 server.
	stateA, messageA, err := s.StartA(clientIdentity, serverIdentity, password, salt, aad)
	if !assert.NoError(t, err) {
		return
	}
	stateB, messageB, err := s.StartB(clientIdentity, []byte("another_server"), verifier, aad)
	if !assert.NoError(t, err) {
		return
	}

	// A and B verify the incoming message from each other.
	sharedSecretA, err := stateA.Finish(messageB)
	if !assert.NoError(t, err) {
		return
	}
	sharedSecretB, err := stateB.Finish(messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A verifies the confirmation message from B - and fails.
	confirmationB := sharedSecretB.Confirmation()
	err = sharedSecretA.Verify(confirmationB)
	assert.Error(t, err)
}

func TestSpake2Scrypt(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2Scrypt(t, s, mhfScrypt)
	}
}

func TestSPAKE2WithWrongPasswordScrypt(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2WithWrongPasswordScrypt(t, s, mhfScrypt)
	}
}

func TestSPAKE2WithWrongClientIdentityScrypt(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2WithWrongClientIdentityScrypt(t, s, mhfScrypt)
	}
}

func TestSPAKE2WithWrongServerIdentityScrypt(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2WithWrongServerIdentityScrypt(t, s, mhfScrypt)
	}
}

func benchSPAKE2Scrypt(b *testing.B, testSuite Suite, mhf suite.MHF) {
	suite := testSuite(mhf)
	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("this_is_a_test_password")
	salt := []byte("NaCl")
	aad := []byte("")

	// Creates a SPAKE2 client and a SPAKE2 server.
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Creates a SPAKE2 instance
		s := New(suite)
		verifier, _ := s.ComputeVerifier(password, salt)
		// Creates a SPAKE2 client and a SPAKE2 server.
		stateA, messageA, _ := s.StartA(clientIdentity, serverIdentity, password, salt, aad)
		stateB, messageB, _ := s.StartB(clientIdentity, serverIdentity, verifier, aad)

		// A and B verify the incoming message from each other.
		sharedSecretA, _ := stateA.Finish(messageB)
		sharedSecretB, _ := stateB.Finish(messageA)

		// A and B verify the confirmation message from each other.
		confirmationA := sharedSecretA.Confirmation()
		confirmationB := sharedSecretB.Confirmation()

		sharedSecretA.Verify(confirmationB)
		sharedSecretB.Verify(confirmationA)
	}
}

func BenchmarkSPAKE2Ed25519Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, Ed25519Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2Ed448Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, Ed448Sha512HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2P256Sha256Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, P256Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2P384Sha256Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, P384Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2P256Sha512Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, P256Sha512HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2P384Sha512Scrypt(b *testing.B) {
	benchSPAKE2Scrypt(b, P384Sha512HkdfHmac, mhfScrypt)
}
