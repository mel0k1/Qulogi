package discover

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func sampleDirectory() *Directory {
	return &Directory{
		Updated: time.Now().UTC(),
		TTLMin:  60,
		Relays: []Relay{
			{
				ID:     "relay-1",
				Region: "eu",
				Transports: []Transport{
					{Type: "qulogi-tls", Addr: "r1.example.com:443", SNI: "vkvideo.ru"},
				},
			},
		},
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := sampleDirectory()
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if d.Sig == "" {
		t.Fatal("signature not set")
	}
	if err := d.Verify(pub, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := sampleDirectory()
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	d.Relays[0].ID = "evil-relay"
	if err := d.Verify(pub, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyUnsigned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	d := sampleDirectory()
	if err := d.Verify(pub, time.Now()); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("want ErrNoSignature, got %v", err)
	}
}

func TestVerifyExpiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := sampleDirectory()
	d.Updated = time.Now().UTC().Add(-2 * time.Hour)
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(pub, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestValidateRejectsBrokenCatalogs(t *testing.T) {
	d := sampleDirectory()
	d.Version = 99
	if err := d.Validate(); err == nil {
		t.Fatal("want version error")
	}
	d = sampleDirectory()
	d.Relays[0].Transports = nil
	if err := d.Validate(); err == nil {
		t.Fatal("want transports error")
	}
	d = sampleDirectory()
	d.Relays = append(d.Relays, d.Relays[0])
	if err := d.Validate(); err == nil {
		t.Fatal("want duplicate id error")
	}
}
