package spake2

import (
	"errors"
	"github.com/jtejido/spake2/internal/suite"
)

type SharedSecret struct {
	suite                                  suite.CipherSuite
	transcript                             []byte
	sharedSecret                           []byte
	keySecret                              []byte
	keyConfirmation, remoteKeyConfirmation []byte
	confirmation, remoteConfirmation       []byte
}

func newSharedSecret(transcript, sharedSecret, keySecret, keyConfirmation, remoteKeyConfirmation []byte, s suite.CipherSuite) *SharedSecret {
	return &SharedSecret{s, transcript, sharedSecret, keySecret, keyConfirmation, remoteKeyConfirmation, nil, nil}
}

func (s *SharedSecret) generateConfirmations() {
	s.confirmation = s.suite.Mac(s.transcript, s.keyConfirmation)
	s.remoteConfirmation = s.suite.Mac(s.transcript, s.remoteKeyConfirmation)
}

func (s *SharedSecret) Confirmation() []byte {
	if s.confirmation == nil {
		s.generateConfirmations()
	}

	return s.confirmation
}

func (s *SharedSecret) Verify(incomingConfirmation []byte) error {
	if s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	if !s.suite.MacEqual(incomingConfirmation, s.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

func (s SharedSecret) Bytes() []byte {
	return s.sharedSecret
}
