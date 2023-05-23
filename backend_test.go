package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// keycloak admin user/pass
// admin/admin
const (
	keycloakUsername = "admin"
	keycloakPassword = "admin"

	vaultClientId     = "vault"
	vaultClientSecret = "vault123"
	basicTfSetup      = `
	terraform {
	   required_providers {
		 keycloak = {
		   source = "mrparkers/keycloak"
		   version = "4.2.0"
		 }
	   }
	 }
	 
	 provider "keycloak" {
		 # set by environment variables
		 client_id     = "admin-cli"
		 username      = "admin"
		 password      = "admin"
		 url           = "http://keycloak:8080"
	
	 }

	 data "keycloak_realm" "realm" {
		 realm = "master"
	 }
	 data "keycloak_role" "admin" {
		realm_id = data.keycloak_realm.realm.id
		name     = "admin"
	 }
	  
	 resource "keycloak_openid_client" "openid_client" {
		realm_id            =  data.keycloak_realm.realm.id
		client_id           = "vault"
		client_secret 		= "vault123"
		enabled             = true
		access_type         = "CONFIDENTIAL"
		service_accounts_enabled = true	
	}
	resource "keycloak_openid_client_service_account_realm_role" "client_service_account_role" {
		realm_id                = data.keycloak_realm.realm.id
		service_account_user_id = keycloak_openid_client.openid_client.service_account_user_id
		role                    = data.keycloak_role.admin.name
	}
   
   `
)

// inspired by https://github.com/hashicorp/vault/blob/main/builtin/logical/rabbitmq/backend_test.go

func prepareLegacyKeycloakTestContainer(t *testing.T) (func(), string, string, string, string) {

	t.Helper()
	realm := "master"

	ctx := context.Background()
	networkName, cleanupNetwork := createTestingNetwork(t, ctx)

	keycloakC, cleanupKeycloak := startLegacyKeycloak(t, ctx, networkName)

	ip, err := keycloakC.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get keycloak container ip: %s", err)
	}
	port, err := keycloakC.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("Failed to get keycloak container port: %s", err)
	}
	serverUrl := fmt.Sprintf("http://%s:%s/auth", ip, port.Port())

	applyTerraform(t, ctx, networkName, basicTfSetup, nil, "/auth")

	//serverUrl := "http://localhost:8080"
	return func() {
		cleanupKeycloak()
		cleanupNetwork()
	}, serverUrl, realm, vaultClientId, vaultClientSecret
}

func prepareKeycloakTestContainer(t *testing.T, version string) (func(), string, string, string, string) {

	t.Helper()
	realm := "master"

	ctx := context.Background()
	networkName, cleanupNetwork := createTestingNetwork(t, ctx)

	keycloakC, cleanupKeycloak := startKeycloakWithVersion(t, ctx, networkName, version)

	ip, err := keycloakC.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get keycloak container ip: %s", err)
	}
	port, err := keycloakC.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("Failed to get keycloak container port: %s", err)
	}
	serverUrl := fmt.Sprintf("http://%s:%s", ip, port.Port())

	applyTerraform(t, ctx, networkName, basicTfSetup, nil, "")

	//serverUrl := "http://localhost:8080"
	return func() {
		cleanupKeycloak()
		cleanupNetwork()
	}, serverUrl, realm, vaultClientId, vaultClientSecret
}
func TestBackend_basic_on_legacy(t *testing.T) {
	b, _ := Factory(context.Background(), logical.TestBackendConfig())

	cleanup, server_url, realm, client_id, client_secret := prepareLegacyKeycloakTestContainer(t)
	defer cleanup()

	logicaltest.Test(t, logicaltest.TestCase{
		PreCheck:       testAccPreCheckFunc(t, server_url),
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, server_url, realm, client_id, client_secret),
			testAccStepReadConfig(t, server_url, realm, client_id, client_secret),
			testAccStepReadSecret(t, client_id, client_secret),
			testAccStepConfigDelete(t),
		},
	})
}
func TestBackendWithKeycloak(t *testing.T) {
	versions := []string{"21.1.1", "20.0.5", "19.0.3"}

	for _, version := range versions {
		t.Run(fmt.Sprintf("Keycloak %s", version), func(t *testing.T) {
			b, _ := Factory(context.Background(), logical.TestBackendConfig())

			cleanup, serverURL, realm, clientID, clientSecret := prepareKeycloakTestContainer(t, version)
			defer cleanup()

			logicaltest.Test(t, logicaltest.TestCase{
				PreCheck:       testAccPreCheckFunc(t, serverURL),
				LogicalBackend: b,
				Steps: []logicaltest.TestStep{
					testAccStepConfig(t, serverURL, realm, clientID, clientSecret),
					testAccStepReadConfig(t, serverURL, realm, clientID, clientSecret),
					testAccStepReadSecret(t, clientID, clientSecret),
					testAccStepConfigDelete(t),
				},
			})
		})
	}
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
func testAccStepConfigDelete(t *testing.T) logicaltest.TestStep {

	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "config/connection",
	}
}
func testAccStepReadConfig(t *testing.T, server_url, realm, client_id, client_secret string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config/connection",
		Check: func(r *logical.Response) error {
			var d struct {
				Realm        string `mapstructure:"realm"`
				ServerUrl    string `mapstructure:"server_url"`
				ClientId     string `mapstructure:"client_id"`
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
			if d.ClientSecret != client_secret {
				return fmt.Errorf("secret was not as expected: %s", d.ClientSecret)
			}
			if d.ClientId != client_id {
				return fmt.Errorf("id was not as expected: %s", d.ClientId)
			}
			if d.ServerUrl != server_url {
				return fmt.Errorf("server_url was not as expected: %s", d.ServerUrl)
			}
			if d.Realm != realm {
				return fmt.Errorf("secret was not as expected: %s", d.Realm)
			}
			return nil
		},
	}
}

func testAccStepReadSecret(t *testing.T, clientId string, expectedClientSecret string) logicaltest.TestStep {
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

func startKeycloakWithVersion(t *testing.T, ctx context.Context, networkName string, keycloakVersion string) (testcontainers.Container, func()) {
	keycloakContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{

			Image:        fmt.Sprintf("quay.io/keycloak/keycloak:%s", keycloakVersion),
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/").WithMethod("GET").WithPort(nat.Port("8080")).WithStartupTimeout(time.Second * 90),
			Env: map[string]string{
				"KEYCLOAK_ADMIN":          "admin",
				"KEYCLOAK_ADMIN_PASSWORD": "admin",
			},
			Cmd: []string{"start-dev"},
			Networks: []string{
				networkName,
			},
			NetworkAliases: map[string][]string{
				networkName: {"keycloak"},
			},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("Failed to start keycloak container: %s", err)
	}
	return keycloakContainer, func() {
		if err := keycloakContainer.Terminate(ctx); err != nil {
			t.Errorf("failed to terminate container: %s", err.Error())
		}
	}
}

func startLegacyKeycloak(t *testing.T, ctx context.Context, networkName string) (testcontainers.Container, func()) {
	keycloakC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "jboss/keycloak:16.1.1",
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/").WithMethod("GET").WithPort(nat.Port("8080")).WithStartupTimeout(time.Second * 90),
			Env: map[string]string{
				"KEYCLOAK_USER":     keycloakUsername,
				"KEYCLOAK_PASSWORD": keycloakPassword,
				"DB_VENDOR":         "H2",
			},
			Networks: []string{
				networkName,
			},
			NetworkAliases: map[string][]string{
				networkName: {"keycloak"},
			},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("Failed to start keycloak container: %s", err)
	}
	return keycloakC, func() {
		if err := keycloakC.Terminate(ctx); err != nil {
			t.Errorf("failed to terminate container: %s", err.Error())
		}
	}

}
func createTestingNetwork(t *testing.T, ctx context.Context) (string, func()) {

	t.Helper()

	// random network name
	networkName := fmt.Sprintf("test-network-%s", uuid.New().String())

	newNetwork, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           networkName,
			CheckDuplicate: true,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create network: %s", err)
	}
	return networkName, func() {
		if err := newNetwork.Remove(ctx); err != nil {
			t.Errorf("failed to remove network: %s", err.Error())
		}
	}
}

func applyTerraform(t *testing.T, ctx context.Context, networkName string, terraformContent string, vars map[string]interface{}, basePath string) {

	t.Helper()

	content := []byte(terraformContent)

	env := map[string]string{}

	if basePath != "" {
		env["KEYCLOAK_BASE_PATH"] = basePath
	}

	req := testcontainers.ContainerRequest{
		Image:      "hashicorp/terraform:latest",
		WaitingFor: wait.ForLog("Apply complete!").WithStartupTimeout(time.Second * 30),

		Entrypoint: []string{"sh", "-c", "cd /opt && terraform init -backend=false && terraform apply -auto-approve"},
		Networks: []string{
			networkName,
		},
		Env: env,
	}

	terraformC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          false,
	})
	defer func() {
		if err := terraformC.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}()

	if err != nil {
		t.Errorf("Failed to start terraform container: %s", err)
	}

	err = terraformC.CopyToContainer(ctx, content, "/opt/main.tf", 777)

	if err != nil {
		t.Fatalf("Failed to copy file: %s", err)
	}
	// copy vars to config.auto.tfvars.json
	if vars != nil {
		varsContent, err := json.Marshal(vars)
		if err != nil {
			t.Fatalf("Failed to marshal vars: %s", err)
		}
		err = terraformC.CopyToContainer(ctx, varsContent, "/opt/config.auto.tfvars.json", 777)
		if err != nil {
			t.Fatalf("Failed to copy vars: %s", err)
		}
	}

	err = terraformC.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start container: %s", err)
	}

}

// create test with code from clipboard
func TestIt(t *testing.T) {
	ctx := context.Background()

	networkName, cleanupNetwork := createTestingNetwork(t, ctx)
	defer cleanupNetwork()

	// start keycloak
	keycloakC, cleanupKeycloak := startKeycloakWithVersion(t, ctx, networkName, "21.1.1")
	defer cleanupKeycloak()

	applyTerraform(t, ctx, networkName, `terraform {
		required_providers {
		  keycloak = {
			source  = "mrparkers/keycloak"
			version = "4.2.0"
		  }
		}
	  }
	  
	  provider "keycloak" {
		# set by environment variables
		client_id = "admin-cli"
		username  = "admin"
		password  = "admin"
		url       = "http://keycloak:8080"
	  }
	  locals {
		realms = ["realm-a", "realm-b"]
	  }
	  
	  data "keycloak_realm" "realm" {
		realm = "master"
	  }
	  
	  
	  resource "keycloak_openid_client" "vault_client" {
		realm_id                 = data.keycloak_realm.realm.id
		client_id                = "vault"
		client_secret            = "vault123"
		enabled                  = true
		access_type              = "CONFIDENTIAL"
		service_accounts_enabled = true
	  }
	  
	  resource "keycloak_realm" "realm" {
		for_each = toset(local.realms)
		realm    = each.key
		enabled  = true
	  }
	  
	  resource "keycloak_openid_client" "some_client" {
		for_each                 = keycloak_realm.realm
		realm_id                 = keycloak_realm.realm[each.key].id
		client_id                = "some-client"
		client_secret            = "some-client-secret123"
		enabled                  = true
		access_type              = "CONFIDENTIAL"
		service_accounts_enabled = true
	  }
	  data "keycloak_openid_client" "realm_client" {
		for_each  = keycloak_realm.realm
		realm_id  = data.keycloak_realm.realm.id
		client_id = "${each.value.realm}-realm"
	  }
	  
	  
	  resource "keycloak_openid_client_service_account_role" "view_clients_role_for_realm_client" {
		realm_id                = data.keycloak_realm.realm.id
		service_account_user_id = keycloak_openid_client.vault_client.service_account_user_id
	  
	  
		for_each = data.keycloak_openid_client.realm_client
	  
		client_id = each.value.id
		role      = "view-clients"
	  }
	  `, nil, "")

	gocaloClient := buildClient(t, ctx, keycloakC, "")
	// get access token and read client secret of client named "client" in realm "realm1" and "realm2"

	//TODO: figure out which

	realms := []string{"realm-a", "realm-b"}
	for _, realm := range realms {

		accessToken, err := gocaloClient.LoginClient(ctx, vaultClientId, vaultClientSecret, "master")

		require.NoError(t, err, "Failed to get access token: %s", err)
		require.NotEmpty(t, accessToken, "Access token is empty")

		clientID := "some-client"
		clients, err := gocaloClient.GetClients(ctx, accessToken.AccessToken, realm, gocloak.GetClientsParams{
			ClientID: &clientID,
		})

		require.NoError(t, err, "Failed to get clients: %s", err)
		require.NotEmpty(t, clients, "Clients is empty")
		require.Len(t, clients, 1, "Clients is empty")

		// get client secret of client named "client" in realm "realm2"
		clientSecretRealm, err := gocaloClient.GetClientSecret(ctx, accessToken.AccessToken, realm, *clients[0].ID)

		assert.NoError(t, err, "Failed to get client secret")

		assert.Equal(t, "some-client-secret123", *clientSecretRealm.Value, "Client does not have expected secret")
	}
}

func buildClient(t *testing.T, ctx context.Context, keycloakC testcontainers.Container, basePath string) *gocloak.GoCloak {
	t.Helper()
	ip, err := keycloakC.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container ip: %s", err)
	}
	port, err := keycloakC.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("Failed to get mapped port: %s", err)
	}
	return gocloak.NewClient(fmt.Sprintf("http://%s:%s%s", ip, port.Port(), basePath))

}
