package iron

import (
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

var (
	errUnpaddedString = errors.New("malformed ticket payload")
)

// Generates a byte slice containing the specified number of random bits.
func randomBits(bits int) (results []byte, err error) {
	results = make([]byte, bits/8)
	if _, err = io.ReadFull(rand.Reader, results); err != nil {
		return
	}
	return
}

// Generates a random, hex-encoded salt.
func generateSalt(saltBits int) (salt []byte, err error) {
	saltBytes, err := randomBits(saltBits)
	if err != nil {
		return
	}
	salt = make([]byte, hex.EncodedLen(len(saltBytes)))
	hex.Encode(salt, saltBytes)
	return
}

// Appends PKCS#7 (RFC 2315, sec. 10.3) padding to the given `data` block.
// Node (via OpenSSL) pads by default; Go requires explicit padding. Returns
// a padded copy of the `data` block.
func addPadding(data []byte) (results []byte) {
	paddingSize := aes.BlockSize
	if m := len(data) % aes.BlockSize; m != 0 {
		paddingSize -= m
	}
	results = make([]byte, len(data)+paddingSize)
	index := copy(results, data)
	for ; index < len(results); index++ {
		results[index] = byte(paddingSize)
	}
	return
}

// Strips PKCS#7 padding from the decrypted `data` block. Returns an unpadded
// copy to avoid retaining the backing padded array in memory.
func removePadding(data []byte) (results []byte) {
	paddingSize := int(data[len(data)-1])
	results = make([]byte, len(data)-paddingSize)
	copy(results, data)
	return
}

// Generates a derived key of `keyBits` from the given `salt` and non-random
// `password`.
func deriveKey(password, salt []byte, keyBits, iterations int) []byte {
	// Node (via OpenSSL) uses HMAC-SHA1; Go allows specifying a different hash
	// function.
	return pbkdf2.Key(password, salt, iterations, keyBits/8, sha1.New)
}

// Decrypts an encrypted `data` block with the given `salt` and `iv`.
// `password`, `keyBits`, and `iterations` will be used to generate the
// derived decryption key.
func decrypt(data, password, salt, iv []byte, keyBits, iterations int) ([]byte, error) {
	key := deriveKey(password, salt, keyBits, iterations)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errUnpaddedString
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return removePadding(data), nil
}

// Generates a salt, derived key, and random IV, then encrypts the given
// `data` block with AES-256-CBC. `keyBits` should be 32 for AES-256, or 16
// for AES-128.
func encrypt(data, password []byte, keyBits, saltBits, ivBits, iterations int) (encrypted, salt, iv []byte, err error) {
	if salt, err = generateSalt(saltBits); err != nil {
		return
	}
	if iv, err = randomBits(ivBits); err != nil {
		return
	}
	key := deriveKey(password, salt, keyBits, iterations)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted = addPadding(data)
	mode.CryptBlocks(encrypted, encrypted)
	return
}

// Derives a key from the given `password` and computes the HMAC-SHA256 digest
// of the given `data` block. Returns the digest in URL-encoded Base64 form.
func createDigest(data, password, salt []byte, keyBits, iterations int) (digest []byte, err error) {
	key := deriveKey(password, salt, keyBits, iterations)
	mac := hmac.New(sha256.New, key)
	if _, err = mac.Write(data); err != nil {
		return
	}
	sum := mac.Sum(nil)
	return encode64(sum), nil
}
