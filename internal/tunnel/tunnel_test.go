package tunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestStreamRoundtrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	psk := []byte("roundtrip-key")
	errs := make(chan error, 1)
	go func() {
		sk, err := serverHandshake(s, psk)
		if err != nil {
			errs <- err
			return
		}
		defer sk.Close()
		data, err := io.ReadAll(sk)
		if err != nil {
			errs <- err
			return
		}
		if len(data) != 200000 {
			t.Errorf("length = %d, want 200000", len(data))
			errs <- nil
			return
		}
		for i, b := range data {
			if b != byte(i%251) {
				t.Errorf("byte %d = %x, want %x", i, b, byte(i%251))
				break
			}
		}
		errs <- nil
	}()

	ck, err := clientHandshake(c, psk)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 200000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := ck.Write(payload); err != nil {
		t.Fatal(err)
	}
	ck.Close()

	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAuthReject(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errs := make(chan error, 1)
	go func() {
		sk, err := serverHandshake(s, []byte("wrong-key"))
		if err != nil {
			errs <- err
			return
		}
		defer sk.Close()
		_, err = ReadAddress(sk)
		errs <- err
	}()

	ck, err := clientHandshake(c, []byte("right-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAddress(ck, Address{Host: "example.com", Port: 443}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("auth unexpectedly passed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAddressCodec(t *testing.T) {
	cases := []Address{
		{Host: "example.com", Port: 443},
		{Host: "1.2.3.4", Port: 80},
		{Host: "2001:db8::1", Port: 8080},
	}
	for _, want := range cases {
		c, s := net.Pipe()
		done := make(chan Address, 1)
		errs := make(chan error, 1)
		go func() {
			addr, err := ReadAddress(s)
			if err != nil {
				errs <- err
				s.Close()
				return
			}
			done <- addr
			s.Close()
		}()
		if err := WriteAddress(c, want); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-done:
			if got.String() != want.String() {
				t.Fatalf("got %s, want %s", got.String(), want.String())
			}
		case err := <-errs:
			t.Fatal(err)
		}
		c.Close()
	}
}
