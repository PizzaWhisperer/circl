package hpke

import (
	"bytes"
	"testing"
)

func contextEqual(a, b *encdecCtx) bool {
	an := make([]byte, a.NonceSize())
	bn := make([]byte, b.NonceSize())
	ac := a.AEAD.Seal(nil, an, nil, nil)
	bc := b.AEAD.Seal(nil, bn, nil, nil)
	return bytes.Equal(a.raw, b.raw) &&
		a.suite == b.suite &&
		bytes.Equal(a.exporterSecret, b.exporterSecret) &&
		bytes.Equal(a.key, b.key) &&
		bytes.Equal(a.baseNonce, b.baseNonce) &&
		bytes.Equal(a.seq, b.seq) &&
		bytes.Equal(ac, bc)
}

func TestContextSerialization(t *testing.T) {
	s := Suite{
		DHKemP384HkdfSha384,
		HkdfSha384,
		AeadAES256GCM,
	}
	info := []byte("some info string")

	pk, sk, err := s.KemID.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := s.NewReceiver(sk, info)
	if err != nil {
		t.Fatal(err)
	}

	sender, err := s.NewSender(pk, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup()
	if err != nil {
		t.Fatal(err)
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}

	rawSealer, err := sealer.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	rawOpener, err := opener.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	parsedSealer, err := UnmarshalSealer(rawSealer)
	if err != nil {
		t.Fatal(err)
	}

	if !contextEqual(
		sealer.(*sealCtx).encdecCtx,
		parsedSealer.(*sealCtx).encdecCtx) {
		t.Error("parsed sealer does not match original")
	}

	parsedOpener, err := UnmarshalOpener(rawOpener)
	if err != nil {
		t.Fatal(err)
	}

	if !contextEqual(
		opener.(*openCtx).encdecCtx,
		parsedOpener.(*openCtx).encdecCtx) {
		t.Error("parsed opener does not match original")
	}
}
