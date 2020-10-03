package spake2

import (
	"bytes"
	"encoding/binary"
	"github.com/jtejido/spake2/internal/suite"
)

func appendLenAndContent(b *bytes.Buffer, input []byte) {
	binary.Write(b, binary.LittleEndian, uint64(len(input)))
	b.Write(input)
}

func computeW(s suite.CipherSuite, password, salt []byte) (suite.Scalar, error) {
	wBytes, err := s.Mhf(password, salt)
	if err != nil {
		return nil, err
	}
	wSc := s.Group().Scalar()
	err = wSc.FromBytes(wBytes)
	return wSc, err
}

func confirmationMACs(ka, aad []byte, s suite.CipherSuite) ([]byte, []byte) {
	info := []byte("ConfirmationKeys")
	info = append(info, aad...)
	Kc := s.DeriveKey(nil, ka, info)
	keyLength := len(Kc)
	return Kc[:keyLength/2], Kc[keyLength/2:]
}

func isElementSmall(s suite.CipherSuite, elem suite.Element) bool {
	return s.Group().ClearCofactor(elem).Equal(s.Group().Element().Identity())
}

// 4.  Key Schedule and Key Confirmation
//
//    The protocol transcript TT, as defined in Section Section 3.3, is
//    unique and secret to A and B.  Both parties use TT to derive shared
//    symmetric secrets Ke and Ka as Ke || Ka = Hash(TT), with |Ke| = |Ka|.
//    The length of each key is equal to half of the digest output, e.g.,
//    128 bits for SHA-256.
//
//    Both endpoints use Ka to derive subsequent MAC keys for key
//    confirmation messages.  Specifically, let KcA and KcB be the MAC keys
//    used by A and B, respectively.  A and B compute them as KcA || KcB =
//    KDF(nil, Ka, "ConfirmationKeys" || AAD), where AAD is the associated
//    data each given to each endpoint, or nil if none was provided.  The
//    length of each of KcA and KcB is equal to half of the KDF output,
//    e.g., |KcA| = |KcB| = 128 bits for HKDF(SHA256).
//
//    The resulting key schedule for this protocol, given transcript TT and
//    additional associated data AAD, is as follows.
//
//        TT  -> Hash(TT) = Ka || Ke
//        AAD -> KDF(nil, Ka, "ConfirmationKeys" || AAD) = KcA || KcB
//
//    A and B output Ke as the shared secret from the protocol.  Ka and its
//    derived keys are not used for anything except key confirmation.
func generateSharedSecrets(s suite.CipherSuite, idA, idB, S, T, K, w, aad []byte) (transcript, Ke, Ka, kcA, kcB []byte) {
	// transcript = len(A) || A || len(B) || B || len(S) || S || len(T) || T || len(K) || K || len(w) || w
	t := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(t, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(t, idB)
	}
	appendLenAndContent(t, S)
	appendLenAndContent(t, T)
	appendLenAndContent(t, K)
	appendLenAndContent(t, w)

	transcript = t.Bytes()
	transcriptHash := s.HashDigest(transcript)
	blockSize := len(transcriptHash)

	Ke, Ka = transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]
	kcA, kcB = confirmationMACs(Ka, aad, s)
	return
}
