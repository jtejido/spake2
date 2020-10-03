package spake2

import (
	"errors"
	"github.com/jtejido/spake2/internal/suite"
	"github.com/jtejido/spake2/internal/suite/ed25519"
	"github.com/jtejido/spake2/internal/suite/ed448"
	"github.com/jtejido/spake2/internal/suite/elliptic"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

type Spake2 struct {
	suite suite.CipherSuite
}

func New(s suite.CipherSuite) *Spake2 {
	return &Spake2{s}
}

type State interface {
	Finish([]byte) (*SharedSecret, error)
}

type state struct {
	suite    suite.CipherSuite
	xOry     suite.Scalar
	idA      []byte
	idB      []byte
	verifier suite.Scalar
	msg      []byte
	aad      []byte
}

type A struct {
	state
}

type B struct {
	state
}

func (s Spake2) ComputeVerifier(password, salt []byte) ([]byte, error) {
	w, err := computeW(s.suite, password, salt)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (s Spake2) StartA(idA, idB, password, salt, aad []byte) (State, []byte, error) {
	x, err := s.suite.Group().RandomScalar()
	if err != nil {
		return nil, []byte{}, err
	}

	w, err := computeW(s.suite, password, salt)
	if err != nil {
		return nil, []byte{}, err
	}

	// X=x*P
	X := s.suite.Group().Element().ScalarMult(x, nil)
	// T=w*M+X
	T := s.suite.Group().Element().ScalarMult(w, s.suite.Group().M())
	T.Add(T, X)

	TBytes := T.Bytes()
	ret := new(A)
	ret.suite = s.suite
	ret.xOry = x
	ret.idA = idA
	ret.idB = idB
	ret.verifier = w
	ret.msg = TBytes
	ret.aad = aad
	return ret, TBytes, nil
}

func (a A) Finish(S []byte) (*SharedSecret, error) {
	B := a.suite.Group().Element()
	err := B.FromBytes(S)
	if err != nil {
		return nil, err
	}

	// A calculates K as h*x*(S-w*N)
	h := a.suite.Group().CofactorScalar()
	wneg := a.suite.Group().Scalar().Negate(a.verifier)
	tmp := a.suite.Group().Element().ScalarMult(wneg, a.suite.Group().N())
	tmp.Add(B, tmp)

	k := a.suite.Group().Element().ScalarMult(a.xOry, tmp)
	k.ScalarMult(h, k)
	kBytes := k.Bytes()
	return newClientSharedSecret(a.suite, a.idA, a.idB, S, a.msg, kBytes, a.verifier.Bytes(), a.aad), nil
}

func newClientSharedSecret(s suite.CipherSuite, idA, idB, S, T, K, w, aad []byte) *SharedSecret {
	transcript, Ke, Ka, kcA, kcB := generateSharedSecrets(s, idA, idB, S, T, K, w, aad)
	return newSharedSecret(transcript, Ke, Ka, kcA, kcB, s)
}

func (s Spake2) StartB(idA, idB, verifier, aad []byte) (State, []byte, error) {
	y, err := s.suite.Group().RandomScalar()
	if err != nil {
		return nil, []byte{}, err
	}

	w := s.suite.Group().Scalar()
	err = w.FromBytes(verifier)
	if err != nil {
		return nil, []byte{}, err
	}

	// Y=y*P
	Y := s.suite.Group().Element().ScalarMult(y, nil)

	// S=w*N+Y
	S := s.suite.Group().Element().ScalarMult(w, s.suite.Group().N())
	S.Add(S, Y)

	SBytes := S.Bytes()

	ret := new(B)
	ret.suite = s.suite
	ret.xOry = y
	ret.idA = idA
	ret.idB = idB
	ret.verifier = w
	ret.msg = SBytes
	ret.aad = aad
	return ret, SBytes, nil
}

func (b B) Finish(T []byte) (*SharedSecret, error) {
	A := b.suite.Group().Element()
	err := A.FromBytes(T)
	if err != nil {
		return nil, err
	}

	//  K = h*y*(T-w*M)
	h := b.suite.Group().CofactorScalar()
	vneg := b.suite.Group().Scalar().Negate(b.verifier)
	tmp := b.suite.Group().Element().ScalarMult(vneg, b.suite.Group().M())
	tmp.Add(A, tmp)

	k := b.suite.Group().Element().ScalarMult(b.xOry, tmp)
	k.ScalarMult(h, k)
	kBytes := k.Bytes()

	return newServerSharedSecret(b.suite, b.idA, b.idB, b.msg, T, kBytes, b.verifier.Bytes(), b.aad), nil
}

func newServerSharedSecret(s suite.CipherSuite, idA, idB, S, T, K, w, aad []byte) *SharedSecret {
	transcript, Ke, Ka, kcA, kcB := generateSharedSecrets(s, idA, idB, S, T, K, w, aad)
	return newSharedSecret(transcript, Ke, Ka, kcB, kcA, s)
}

func Ed25519Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return ed25519.NewEd25519Sha256HkdfHmac(mhf)
}

func Ed448Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return ed448.NewEd448Sha512HkdfHmac(mhf)
}

func P256Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP256Sha256HkdfHmac(mhf)
}

func P384Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP384Sha256HkdfHmac(mhf)
}

func P256Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP256Sha512HkdfHmac(mhf)
}

func P384Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP384Sha512HkdfHmac(mhf)
}

type Confirmations struct {
	confirmation       []byte
	remoteConfirmation []byte
	suite              suite.CipherSuite
}

func NewConfirmations(confirmation, remoteConfirmation []byte, suite suite.CipherSuite) *Confirmations {
	return &Confirmations{confirmation, remoteConfirmation, suite}
}

func (c Confirmations) Bytes() []byte {
	return c.confirmation
}

func (c Confirmations) Verify(incomingConfirmation []byte) error {
	if !c.suite.MacEqual(incomingConfirmation, c.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

// MHFs
func Scrypt(N, r, p int) suite.MHF {
	return func(password, salt []byte, len int) ([]byte, error) {
		return scrypt.Key(password, salt, N, r, p, len)
	}
}

func Argon2(time, memory uint32, threads uint8) suite.MHF {
	return func(password, salt []byte, len int) ([]byte, error) {
		return argon2.Key(password, salt, time, memory, threads, uint32(len)), nil
	}
}
