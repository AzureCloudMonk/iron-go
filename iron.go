// Package iron is a Go implementation of the Iron library.
package iron

import (
	"errors"
	"time"
)

// Ticket format constants.
const (
	MacFormatVersion = "2"                        // The signature base string version.
	MacPrefix        = "Fe26." + MacFormatVersion // The Iron ticket prefix.
)

// Key and IV sizes.
const (
	AES256KeyBits    = 256 // The AES-256 encryption key size.
	IVBits           = 128 // The AES-256 IV size.
	IntegrityKeyBits = 256 // The HMAC-SHA256 key size.
)

var (
	errUnsupportedPrefix = errors.New("unsupported or invalid ticket prefix")
	errMismatchedHmac    = errors.New("mismatched MAC value")
	errExpired           = errors.New("ticket expired")
	errUnsupportedID     = errors.New("password IDs are not supported")
	errEmptyPassword     = errors.New("empty password")
)

// Algorithm specifies encryption and integrity algorithm options.
type Algorithm struct {
	SaltBits   int // The salt size. Defaults to 256 bits.
	Iterations int // The number of PBKDF2 iterations. Defaults to 1.
}

// Default algorithm options.
var DefaultAlgorithm = Algorithm{
	SaltBits:   256,
	Iterations: 1,
}

// Default integrity algorithm options.
var DefaultsIntegrity = Algorithm{
	SaltBits:   256,
	Iterations: 1,
}

// Options specifies encryption and decryption options.
type Options struct {
	Encryption   Algorithm     // Payload encryption options.
	Integrity    Algorithm     // Signature generation options.
	ExpireIn     time.Duration // Ticket lifetime. If omitted or 0, the ticket will never expire.
	AcceptWithin time.Duration // The window for accepting expired tickets. Defaults to 1 minute.
	LocalOffset  time.Duration // The local clock time offset. Defaults to 0.
}

// Default options.
var Defaults = Options{
	Encryption:   DefaultAlgorithm,
	Integrity:    DefaultAlgorithm,
	ExpireIn:     0,
	AcceptWithin: 1 * time.Minute,
	LocalOffset:  0,
}

// Seal seals a data block with the specified password and options. The
// password is used to derive the encryption and HMAC keys. The resulting
// string can be embedded in a cookie, query parameter, or header.
func Seal(data, password []byte, options Options) (string, error) {
	now := time.Now().Add(options.LocalOffset)
	if len(password) == 0 {
		return "", errEmptyPassword
	}
	encrypted, cryptSalt, iv, err := encrypt(data, password, AES256KeyBits, options.Encryption.SaltBits, IVBits, options.Encryption.Iterations)
	if err != nil {
		return "", err
	}
	encrypted64 := string(encode64(encrypted))
	iv64 := string(encode64(iv))
	var expireAt time.Time
	if options.ExpireIn > 0 {
		expireAt = now.Add(options.ExpireIn)
	}
	t := &ticket{
		macPrefix:   MacPrefix,
		passwordID:  "",
		cryptSalt:   cryptSalt,
		iv64:        iv64,
		encrypted64: encrypted64,
		expireAt:    expireAt,
	}
	return t.Encode(password, IntegrityKeyBits, options.Integrity.SaltBits, options.Integrity.Iterations)
}

// Unseal unseals a sealed string with the specified password and options.
func Unseal(sealed string, password []byte, options Options) ([]byte, error) {
	now := time.Now().Add(options.LocalOffset)
	if len(password) == 0 {
		return nil, errEmptyPassword
	}
	t := new(ticket)
	if err := t.Unmarshal(sealed); err != nil {
		return nil, err
	}
	if t.macPrefix != MacPrefix {
		return nil, errUnsupportedPrefix
	}
	if !t.expireAt.IsZero() && now.Add(-options.AcceptWithin).After(t.expireAt) {
		return nil, errExpired
	}
	if len(t.passwordID) > 0 {
		return nil, errUnsupportedID
	}
	ok, err := t.Verify(password, IntegrityKeyBits, options.Integrity.Iterations)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errMismatchedHmac
	}
	encrypted, err := decodeString64(t.encrypted64)
	if err != nil {
		return nil, err
	}
	iv, err := decodeString64(t.iv64)
	if err != nil {
		return nil, err
	}
	decrypted, err := decrypt(encrypted, password, t.cryptSalt, iv, AES256KeyBits, options.Integrity.Iterations)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
