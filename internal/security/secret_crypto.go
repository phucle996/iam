package security

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func EncryptSecret(plainText, masterKey string) (string, error) {
	key, err := decodeMasterKey(masterKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("security: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("security: create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return "", fmt.Errorf("security: read nonce: %w", err)
	}

	cipherText := gcm.Seal(nil, nonce, []byte(plainText), nil)
	payload := append(nonce, cipherText...)
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func DecryptSecret(cipherPayload, masterKey string) (string, error) {
	key, err := decodeMasterKey(masterKey)
	if err != nil {
		return "", err
	}

	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cipherPayload))
	if err != nil {
		return "", fmt.Errorf("security: decode encrypted secret: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("security: create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("security: create gcm: %w", err)
	}

	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("security: encrypted secret payload too short")
	}

	nonce := raw[:gcm.NonceSize()]
	cipherText := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", fmt.Errorf("security: decrypt secret: %w", err)
	}

	return string(plain), nil
}

func decodeMasterKey(masterKey string) ([]byte, error) {
	value := strings.TrimSpace(masterKey)
	if value == "" {
		return nil, fmt.Errorf("security: master key is required")
	}

	if b, err := base64.StdEncoding.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(value) == 32 {
		return []byte(value), nil
	}

	return nil, fmt.Errorf("security: master key must be 32 bytes (base64/raw/hex/plain)")
}
