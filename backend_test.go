package keycloak

import (
	"context"
	"testing"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
)

// inspired by https://github.com/hashicorp/vault/blob/main/builtin/logical/rabbitmq/backend_test.go

func prepareKeycloakTestContainer(t *testing.T) (func(), string) {

	return func() {

	}, "http://localhost:8080"
}

func TestBackend_basic(t *testing.T) {
	b, _ := Factory(context.Background(), logical.TestBackendConfig())

	cleanup, uri := prepareKeycloakTestContainer(t)
	defer cleanup()

	logicaltest.Test(t, logicaltest.TestCase{
		PreCheck:       testAccPreCheckFunc(t, uri),
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, uri),
		},
	})
}
func testAccPreCheckFunc(t *testing.T, uri string) func() {
	return func() {
		if uri == "" {
			t.Fatal("Keycloak URI must be set for acceptance tests")
		}
	}
}

func testAccStepConfig(t *testing.T, uri string) logicaltest.TestStep {
	client_id := "admin"
	client_secret := "admin"
	realm := "demo"
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data: map[string]interface{}{
			"server_url":    uri,
			"realm":         realm,
			"client_id":     client_id,
			"client_secret": client_secret,
		},
	}
}
