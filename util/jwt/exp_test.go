package jwt_test

import (
	"testing"
	"time"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/util/jwt"
	testutil "github.com/Serviceware/vault-plugin-secrets-keycloak/util/test"
)

func TestExpirationTime(t *testing.T) {
	tests := []struct {
		name                string
		token               string
		expectErr           bool
		expectExprationTime time.Time
	}{
		{name: "empty string", expectErr: true},
		{name: "proper token with exp", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzU4NDUwODk1LCJleHAiOjE3NTg0NTQ0OTV9.xRQ-bbnsIp8Pfz34hkW-UzYxs6w-S4qWp_v8-T6J0Fg", expectExprationTime: time.Unix(1758454495, 0)},
		{name: "jwt without exp", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30", expectErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expirationTime, err := jwt.ExpirationTime(test.token)
			if test.expectErr {
				if err == nil {
					t.Fatal("expected error, got <nil>")
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}

			if !expirationTime.Equal(test.expectExprationTime) {
				t.Fatalf("expected %v, got %v", test.expectExprationTime, expirationTime)
			}
		})
	}

}

func TestIsValidIn(t *testing.T) {
	tests := []struct {
		name        string
		jwt         string
		delta       time.Duration
		expectValid bool
	}{
		{name: "empty (malformed) jwt"},
		{name: "jwt without exp", jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"},
		{name: "jwt with malformed exp", jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzU4NDUxNzQ0LCJleHAiOjEuNX0.KROvZ729yGhpxO6x3aSbYYM6KJaBr-xh3JRrvU3En5A"},
		{name: "jwt valid now", jwt: testutil.JWT(5 * time.Second), expectValid: true},
		{name: "jwt not valid later", jwt: testutil.JWT(0), delta: time.Hour, expectValid: false},
		{name: "jwt valid later", jwt: testutil.JWT(60 * time.Second), delta: 30 * time.Second, expectValid: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid := jwt.IsValidIn(test.jwt, test.delta)
			if valid != test.expectValid {
				t.Errorf("expected %t, got %t", test.expectValid, valid)
			}
		})
	}
}
