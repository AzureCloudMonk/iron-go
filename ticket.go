package iron

import (
	"crypto/hmac"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	errMalformedTicket = errors.New("invalid ticket structure")
)

type ticket struct {
	macPrefix   string
	passwordID  string
	cryptSalt   []byte
	iv64        string
	encrypted64 string
	expireAt    time.Time
	macSalt     []byte
	digest      []byte
}

// Generates the signature base string.
func (t *ticket) Base() []byte {
	var expiration string
	if !t.expireAt.IsZero() {
		expiration = strconv.FormatInt(t.expireAt.UnixNano()/1000/1000, 10)
	}
	return []byte(t.macPrefix + "*" + t.passwordID + "*" + string(t.cryptSalt) + "*" + t.iv64 + "*" + t.encrypted64 + "*" + expiration)
}

// Generates a salt, derived key, and digest for the signature base string.
func (t *ticket) Encode(password []byte, keyBits, saltBits, iterations int) (sealed string, err error) {
	macBase := t.Base()
	macSalt, err := generateSalt(saltBits)
	if err != nil {
		return
	}
	t.macSalt = macSalt
	digest, err := createDigest(macBase, password, t.macSalt, keyBits, iterations)
	if err != nil {
		return
	}
	t.digest = digest
	return string(macBase) + "*" + string(t.macSalt) + "*" + string(t.digest), nil
}

// Performs a constant-time comparison to determine if the computed signature
// base string matches the provided base string.
func (t *ticket) Verify(password []byte, keyBits, iterations int) (ok bool, err error) {
	macBase := t.Base()
	digest, err := createDigest(macBase, password, t.macSalt, keyBits, iterations)
	if err != nil {
		return
	}
	return hmac.Equal(digest, t.digest), nil
}

// Parses a sealed string into its individual components.
func (t *ticket) Unmarshal(sealed string) error {
	parts := strings.Split(sealed, "*")
	if len(parts) != 8 {
		return errMalformedTicket
	}
	t.macPrefix = parts[0]
	t.passwordID = parts[1]
	t.cryptSalt = []byte(parts[2])
	t.iv64 = parts[3]
	t.encrypted64 = parts[4]
	// Ticket timestamps are encoded in milliseconds since Epoch; Go provides
	// nanosecond precision for timestamps.
	expiration := parts[5]
	if len(expiration) > 0 {
		ms, err := strconv.ParseInt(expiration, 10, 64)
		if err != nil {
			return err
		}
		t.expireAt = time.Unix(0, ms*1000*1000)
	}
	t.macSalt = []byte(parts[6])
	t.digest = []byte(parts[7])
	return nil
}
