package keycloak

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v8"
	"github.com/docker/go-connections/nat"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// inspired by https://github.com/hashicorp/vault/blob/main/builtin/logical/rabbitmq/backend_test.go

func prepareKeycloakTestContainer(t *testing.T) (func(), string, string, string, string) {

	t.Helper()
	keycloakUsername := "admin"
	keycloakPassword := "admin"
	client_id := "vault"
	client_secret := "vault"
	realm := "master"

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "jboss/keycloak:latest",
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP("/").WithMethod("GET").WithPort(nat.Port("8080")).WithStartupTimeout(time.Second * 90),
		Env: map[string]string{
			"KEYCLOAK_USER":     keycloakUsername,
			"KEYCLOAK_PASSWORD": keycloakPassword,
		},
	}

	keycloakC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := keycloakC.Host(ctx)
	if err != nil {
		t.Error(err)
	}
	port, err := keycloakC.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatal(err)
	}
	serverUrl := fmt.Sprintf("http://%s:%s", ip, port.Port())
	keycloakCLient := gocloak.NewClient(serverUrl)

	loginToken, err := keycloakCLient.Login(ctx, "admin-cli", "", "master", keycloakUsername, keycloakPassword)

	if err != nil {
		t.Fatal(err)
	}
	serviceAccountsEnabled := true

	createClientResponse, err := keycloakCLient.CreateClient(ctx, loginToken.AccessToken, realm, gocloak.Client{
		ClientID:               &client_id,
		Secret:                 &client_secret,
		ServiceAccountsEnabled: &serviceAccountsEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientServiceAccount, err := keycloakCLient.GetClientServiceAccount(ctx, loginToken.AccessToken, realm, createClientResponse)
	if err != nil {
		t.Fatal(err)
	}
	adminRole, err := keycloakCLient.GetRealmRole(ctx, loginToken.AccessToken, realm, "admin")
	if err != nil {
		t.Fatal(err)
	}
	err = keycloakCLient.AddRealmRoleToUser(ctx, loginToken.AccessToken, realm, *clientServiceAccount.ID, []gocloak.Role{*adminRole})

	if err != nil {
		t.Fatal(err)
	}

	//serverUrl := "http://localhost:8080"
	return func() {
		defer keycloakC.Terminate(ctx)
	}, serverUrl, realm, client_id, client_secret
}

func TestBackend_basic(t *testing.T) {
	b, _ := Factory(context.Background(), logical.TestBackendConfig())

	cleanup, server_url, realm, client_id, client_secret := prepareKeycloakTestContainer(t)
	defer cleanup()

	logicaltest.Test(t, logicaltest.TestCase{
		PreCheck:       testAccPreCheckFunc(t, server_url),
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, server_url, realm, client_id, client_secret),

			testAccStepRead(t, client_id, client_secret),
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

func testAccStepConfig(t *testing.T, server_url, realm, client_id, client_secret string) logicaltest.TestStep {

	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data: map[string]interface{}{
			"server_url":    server_url,
			"realm":         realm,
			"client_id":     client_id,
			"client_secret": client_secret,
		},
	}
}
func testAccStepRead(t *testing.T, clientId string, expectedClientSecret string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("client-secret/%s", clientId),
		Check: func(r *logical.Response) error {
			var d struct {
				ClientSecret string `mapstructure:"client_secret"`
			}
			if err := mapstructure.Decode(r.Data, &d); err != nil {
				return err
			}

			if r != nil {
				if r.IsError() {
					return fmt.Errorf("error on resp: %#v", *r)
				}
			}
			if d.ClientSecret != expectedClientSecret {
				return fmt.Errorf("secret was not as expected: %s", d.ClientSecret)
			}
			return nil
		},
	}
}