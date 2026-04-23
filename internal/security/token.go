package security

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrInvalidTokenLength is returned when the requested token length is not positive.
	ErrInvalidTokenLength = errors.New("security: invalid token length")
)

var tokenEncoding = base64.RawURLEncoding

// GenerateToken creates an opaque, URL-safe token with the requested length.
//
// The token is derived from cryptographically secure random bytes and mixed with
// the provided secret via HMAC-SHA256. The returned value is truncated to the
// requested character length.
func GenerateToken(length int, secret string) (string, error) {
	if length <= 0 {
		return "", ErrInvalidTokenLength
	}
	if strings.TrimSpace(secret) == "" {
		return "", ErrEmptySecret
	}

	var builder strings.Builder
	builder.Grow(length)

	var counter uint64
	for builder.Len() < length {
		block, err := generateTokenBlock(secret, counter, cryptorand.Reader)
		if err != nil {
			return "", err
		}

		builder.WriteString(tokenEncoding.EncodeToString(block))
		counter++
	}

	token := builder.String()
	if len(token) > length {
		token = token[:length]
	}

	return token, nil
}

// HashToken returns a deterministic HMAC-SHA256 digest for a token.
func HashToken(token, secret string) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", ErrEmptySecret
	}

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(strings.TrimSpace(token))); err != nil {
		return "", fmt.Errorf("security: hash token: %w", err)
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

func generateTokenBlock(secret string, counter uint64, entropy io.Reader) ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(entropy, seed); err != nil {
		return nil, fmt.Errorf("security: read token entropy: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(seed); err != nil {
		return nil, fmt.Errorf("security: mix token entropy: %w", err)
	}

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	if _, err := mac.Write(counterBytes[:]); err != nil {
		return nil, fmt.Errorf("security: mix token counter: %w", err)
	}

	block := make([]byte, 0, len(seed)+sha256.Size)
	block = append(block, seed...)
	block = append(block, mac.Sum(nil)...)
	return block, nil
}
