package iron

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

type tokenData struct {
	A int        `json:"a"`
	B int        `json:"b"`
	C []int      `json:"c"`
	D nestedData `json:"d"`
}

type nestedData struct {
	E string `json:"e"`
}

var (
	token      = &tokenData{1, 2, []int{3, 4, 5}, nestedData{"f"}}
	password   = []byte("some_not_random_password")
	tokenBytes []byte
)

func init() {
	var err error
	if tokenBytes, err = json.Marshal(token); err != nil {
		panic(err)
	}
}

func TestSeal(t *testing.T) {
	sealed, err := Seal(tokenBytes, password, Defaults)
	if err != nil {
		t.Fatalf("Seal returned error %#v", err)
	}
	unsealed, err := Unseal(sealed, password, Defaults)
	if err != nil {
		t.Fatalf("Unseal returned error %#v", err)
	}
	results := new(tokenData)
	err = json.Unmarshal(unsealed, results)
	if err != nil {
		t.Fatalf("Unmarshal: got %#v; want nil", err)
	}
}

func TestExpiration(t *testing.T) {
	options := Options{
		Encryption:   DefaultAlgorithm,
		Integrity:    DefaultAlgorithm,
		ExpireIn:     200 * time.Millisecond,
		AcceptWithin: 1 * time.Minute,
		LocalOffset:  0,
	}
	sealed, err := Seal(tokenBytes, password, options)
	if err != nil {
		t.Fatalf("expiration: Seal returned error %#v", err)
	}
	unsealed, err := Unseal(sealed, password, Defaults)
	if err != nil {
		t.Fatalf("expiration: Unseal returned error %#v", err)
	}
	results := new(tokenData)
	if err = json.Unmarshal(unsealed, results); err != nil {
		t.Fatalf("expiration: got %#v; want nil", err)
	}
}

func TestExpirationOffset(t *testing.T) {
	options := Options{
		Encryption:   DefaultAlgorithm,
		Integrity:    DefaultAlgorithm,
		ExpireIn:     200 * time.Millisecond,
		AcceptWithin: 1 * time.Minute,
		LocalOffset:  -100 * time.Second,
	}
	sealed, err := Seal(tokenBytes, password, options)
	if err != nil {
		t.Fatalf("expiration and offset: Seal returned error %#v", err)
	}
	unsealed, err := Unseal(sealed, password, options)
	if err != nil {
		t.Fatalf("expiration and offset: Unseal returned error %#v", err)
	}
	if !bytes.Equal(unsealed, tokenBytes) {
		t.Errorf("expiration and offset: got %#v; want %#v", unsealed, tokenBytes)
	}
	results := new(tokenData)
	if err = json.Unmarshal(unsealed, results); err != nil {
		t.Fatalf("expiration and offset: got %#v; want nil", err)
	}
}

func TestUnseal(t *testing.T) {
	sealed := "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(sealed, password, Defaults)
	if err != nil {
		t.Fatalf("Unseal returned error %#v", err)
	}
	if !bytes.Equal(unsealed, tokenBytes) {
		t.Errorf("Unseal: got %#v; want %#v", unsealed, tokenBytes)
	}
}

func TestUnsealMalformed(t *testing.T) {
	malformed := "x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(malformed, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(malformed): got %#v; want nil", unsealed)
	}
	if err != errMalformedTicket {
		t.Errorf("Unseal(malformed): error = %#v, want %#v", err, errMalformedTicket)
	}
}

func TestUnsealMissingPassword(t *testing.T) {
	sealed := "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(sealed, nil, Defaults)
	if unsealed != nil {
		t.Fatalf("missing decryption password: got %#v; want nil", unsealed)
	}
	if err != errEmptyPassword {
		t.Errorf("missing decryption password: error = %#v, want %#v", err, errEmptyPassword)
	}
}

func TestUnsealUnsupportedPrefix(t *testing.T) {
	badPrefix := "Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(badPrefix, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(badPrefix): got %#v; want nil", unsealed)
	}
	if err != errUnsupportedPrefix {
		t.Errorf("Unseal(badPrefix): error = %#v, want %#v", err, errUnsupportedPrefix)
	}
}

func TestUnsealMismatchedHmac(t *testing.T) {
	badHmac := "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCX"
	unsealed, err := Unseal(badHmac, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(badHmac): got %#v; want nil", unsealed)
	}
	if err != errMismatchedHmac {
		t.Errorf("Unseal(badHmac): error = %#v, want %#v", err, errMismatchedHmac)
	}
}

func TestUnsealDecryptionFailure(t *testing.T) {
	badPayload := "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??*ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(badPayload, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(badPayload): got %#v; want nil", unsealed)
	}
	if err == nil {
		t.Errorf("Unseal(badPayload): got nil; want encoding error")
	}
}

func TestUnsealBadIv(t *testing.T) {
	badIv := "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M*ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
	unsealed, err := Unseal(badIv, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(badIv): got %#v; want nil", unsealed)
	}
	if err == nil {
		t.Errorf("Unseal(badIv): got nil; want encoding error")
	}
}

func TestUnsealExpired(t *testing.T) {
	expired := "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060*e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3*xye6M3kTtaSidqRaoWq4FYqym4lH5XvhgmVa5HX8vPM"
	unsealed, err := Unseal(expired, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(expired): got %#v; want nil", unsealed)
	}
	if err != errExpired {
		t.Errorf("Unseal(expired): error = %#v, want %#v", err, errExpired)
	}
}

func TestUnsealBadExpiration(t *testing.T) {
	badExpiration := "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a*e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3*xye6M3kTtaSidqRaoWq4FYqym4lH5XvhgmVa5HX8vPM"
	unsealed, err := Unseal(badExpiration, password, Defaults)
	if unsealed != nil {
		t.Fatalf("Unseal(badExpiration): got %#v; want nil", unsealed)
	}
	if err == nil {
		t.Errorf("Unseal(badExpiration): got nil; want integer conversion error")
	}
}
