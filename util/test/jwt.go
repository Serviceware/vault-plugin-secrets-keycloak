package test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// JWT creates a dummy JWT with iat = now and exp = now + delta for testing
// purposes.
func JWT(delta time.Duration) string {
	now := time.Now().Truncate(time.Second)

	rawHeader := `{"alg":"HS256","typ":"JWT"}`
	rawPayload := fmt.Sprintf(`{"sub":"1234567890","name":"John Doe","iat":%d,"exp":%d}`, now.Unix(), now.Add(delta).Unix())

	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(rawHeader))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))

	message := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)

	secretKey := []byte("a_very_secure_and_long_secret_key")
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s", message, encodedSignature)
}
