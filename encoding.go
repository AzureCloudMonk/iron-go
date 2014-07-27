package iron

import (
	"bytes"
	"encoding/base64"
	"strings"
)

func isPadding64(r rune) bool {
	return r == '='
}

// URL-encodes the `source` byte slice and strips trailing padding
// characters.
func encode64(source []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(source)))
	base64.URLEncoding.Encode(encoded, source)
	return bytes.TrimRightFunc(encoded, isPadding64)
}

// Pads and decodes the Base64-encoded `source` string. Go's Base64
// decoder requires a padded source string.
func decodeString64(source string) ([]byte, error) {
	if m := len(source) % 4; m != 0 {
		source += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(source)
}
