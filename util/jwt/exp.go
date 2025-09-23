package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ExpirationTime is a simple helper function that extracts the expiration
// time claim from jwt and retuns it as [time.Time].
func ExpirationTime(jwt string) (time.Time, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("jwt has != 3 parts")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, err
	}

	parsedPayload := struct {
		Exp *int64 `json:"exp"`
	}{}
	if err = json.Unmarshal(payload, &parsedPayload); err != nil {
		return time.Time{}, err
	} else if parsedPayload.Exp == nil {
		return time.Time{}, fmt.Errorf("jwt has no exp claim")
	}

	return time.Unix(*parsedPayload.Exp, 0), nil
}

// IsValidIn checks whether jwt is still valid in the future at
// now + delta. If the expiration time claim cannot be read
// from jwt, false is returned.
func IsValidIn(jwt string, delta time.Duration) bool {
	expirationTime, err := ExpirationTime(jwt)
	if err != nil {
		return false
	}

	return time.Now().Add(delta).Before(expirationTime)
}
