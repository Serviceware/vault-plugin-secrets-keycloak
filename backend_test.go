package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// keycloak admin user/pass
// admin/admin
const (
	realm            = "master"
	keycloakUsername = "admin"
	keycloakPassword = "admin"

	vaultClientId     = "vault"
	vaultClientSecret = "vault123"

	specificRealm = "specific-realm"

	basicTfSetup = `
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
	tfMultiRealmClientSetup = `terraform {
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
	client_secret            = "some-client-secret123-in-realm-${keycloak_realm.realm[each.key].id}"
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
  `

	tfSpecificRealmClientSetup = `terraform {
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

  resource "keycloak_realm" "sepecific_realm" {
	realm = "specific-realm"
  }
  
  
  resource "keycloak_openid_client" "vault_client" {
	realm_id                 = keycloak_realm.sepecific_realm.id
	client_id                = "vault"
	client_secret            = "vault123"
	enabled                  = true
	access_type              = "CONFIDENTIAL"
	service_accounts_enabled = true
  }
  

  
  resource "keycloak_openid_client" "some_client" {
	realm_id                 = keycloak_realm.sepecific_realm.id
	client_id                = "some-client"
	client_secret            = "some-client-secret123"
	enabled                  = true
	access_type              = "CONFIDENTIAL"
	service_accounts_enabled = true
  }
  data "keycloak_openid_client" "realm_management" {

	realm_id  = keycloak_realm.sepecific_realm.id
	client_id = "realm-management"
  }
  
  
  resource "keycloak_openid_client_service_account_role" "view_clients_role_for_realm_client" {
	realm_id                = keycloak_realm.sepecific_realm.id
	service_account_user_id = keycloak_openid_client.vault_client.service_account_user_id
  
  
  
	client_id = data.keycloak_openid_client.realm_management.id
	role      = "view-clients"
  }
  `
)

func TestBackend_BasicAccess(t *testing.T) {

	keycloakContainerEnvVars := map[string]string{
		"KEYCLOAK_ADMIN":          "admin",
		"KEYCLOAK_ADMIN_PASSWORD": "admin",
	}
	keycloakBasePath := ""
	keyloakLegacyContainerEnvVars := map[string]string{
		"KEYCLOAK_USER":     "admin",
		"KEYCLOAK_PASSWORD": "admin",
		"DB_VENDOR":         "H2",
	}
	keycloakLegacyBasePath := "/auth"
	type test struct {
		keycloakImage string
		cmd           []string
		envVars       map[string]string
		basePath      string
	}

	tests := []test{
		{
			keycloakImage: "quay.io/keycloak/keycloak:21.1.1",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},
		//legacy
		{
			keycloakImage: "jboss/keycloak:16.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
		{
			keycloakImage: "jboss/keycloak:15.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			b, _ := Factory(context.Background(), logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, basicTfSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()

			logicaltest.Test(t, logicaltest.TestCase{
				PreCheck:       testAccPreCheckFunc(t, server_url),
				LogicalBackend: b,
				Steps: []logicaltest.TestStep{
					testAccStepConfig(t, server_url, realm, vaultClientId, vaultClientSecret),
					testAccStepReadConfig(t, server_url, realm, vaultClientId, vaultClientSecret),
					testAccStepReadSecretDeprecated(t, vaultClientId, vaultClientSecret),
					testAccStepConfigDelete(t),
				},
			})
		})
	}
}
func TestBackend_MultiRealmAccess(t *testing.T) {

	keycloakContainerEnvVars := map[string]string{
		"KEYCLOAK_ADMIN":          "admin",
		"KEYCLOAK_ADMIN_PASSWORD": "admin",
	}
	keycloakBasePath := ""
	keyloakLegacyContainerEnvVars := map[string]string{
		"KEYCLOAK_USER":     "admin",
		"KEYCLOAK_PASSWORD": "admin",
		"DB_VENDOR":         "H2",
	}
	keycloakLegacyBasePath := "/auth"
	type test struct {
		keycloakImage string
		cmd           []string
		envVars       map[string]string
		basePath      string
	}

	tests := []test{
		{
			keycloakImage: "quay.io/keycloak/keycloak:21.1.1",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},

		//legacy
		{
			keycloakImage: "jboss/keycloak:16.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
		{
			keycloakImage: "jboss/keycloak:15.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			b, _ := Factory(context.Background(), logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, tfMultiRealmClientSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()

			logicaltest.Test(t, logicaltest.TestCase{
				PreCheck:       testAccPreCheckFunc(t, server_url),
				LogicalBackend: b,
				Steps: []logicaltest.TestStep{
					testAccStepConfig(t, server_url, realm, vaultClientId, vaultClientSecret),
					testAccStepReadConfig(t, server_url, realm, vaultClientId, vaultClientSecret),
					testAccStepReadRealmClientSecret(t, "realm-a", "some-client", "some-client-secret123-in-realm-realm-a", fmt.Sprintf("%s%s", server_url, "/realms/realm-a")),
					testAccStepReadRealmClientSecret(t, "realm-b", "some-client", "some-client-secret123-in-realm-realm-b", fmt.Sprintf("%s%s", server_url, "/realms/realm-b")),
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

func testAccStepConfigForRealm(t *testing.T, server_url, realm, client_id, client_secret string) logicaltest.TestStep {

	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("config/realms/%s/connection", realm),
		Data: map[string]interface{}{
			"server_url":    server_url,
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

func testAccStepReadConfigForRealm(t *testing.T, server_url, realm, client_id, client_secret string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("config/realms/%s/connection", realm),
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

func testAccStepReadSecretDeprecated(t *testing.T, clientId string, expectedClientSecret string) logicaltest.TestStep {
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
func testAccStepReadRealmClientSecret(t *testing.T, realm string, clientId string, expectedClientSecret string, expectedIssuer string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("realms/%s/clients/%s/secret", realm, clientId),
		Check: func(r *logical.Response) error {
			var d struct {
				ClientSecret string `mapstructure:"client_secret"`
				ClientId     string `mapstructure:"client_id"`
				Issuer       string `mapstructure:"issuer"`
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
			if d.ClientId != clientId {
				return fmt.Errorf("id was not as expected: %s", d.ClientId)
			}
			if d.Issuer != expectedIssuer {
				return fmt.Errorf("issuer was %s, expected: %s", d.Issuer, expectedIssuer)
			}
			return nil
		},
	}
}
func testAccStepReadRealmWellknownOpenIdConfig(t *testing.T, realm string, expectedIssuer string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("realms/%s/openid-configuration", realm),
		Check: func(r *logical.Response) error {
			var d struct {
				Issuer string `mapstructure:"issuer"`
			}
			if err := mapstructure.Decode(r.Data, &d); err != nil {
				return err
			}

			if r != nil {
				if r.IsError() {
					return fmt.Errorf("error on resp: %#v", *r)
				}
			}
			if d.Issuer != expectedIssuer {
				return fmt.Errorf("secret was not as expected: %s", d.Issuer)
			}
			return nil
		},
	}
}

func prepareKeycloakTestContainer(t *testing.T, image, tfContent, basePath string, cmd []string, keycloakEnv map[string]string) (func(), string) {

	t.Helper()

	ctx := context.Background()
	networkName, cleanupNetwork := createTestingNetwork(t, ctx)

	keycloakC, cleanupKeycloak := startKeycloak(t, ctx, image, cmd, keycloakEnv, networkName)

	ip, err := keycloakC.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get keycloak container ip: %s", err)
	}
	port, err := keycloakC.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("Failed to get keycloak container port: %s", err)
	}
	serverUrl := fmt.Sprintf("http://%s:%s%s", ip, port.Port(), basePath)

	applyTerraform(t, ctx, networkName, tfContent, nil, basePath)

	//serverUrl := "http://localhost:8080"
	return func() {
		cleanupKeycloak()
		cleanupNetwork()
	}, serverUrl
}

func startKeycloak(t *testing.T, ctx context.Context, image string, cmd []string, env map[string]string, networkName string) (testcontainers.Container, func()) {
	keycloakC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/").WithMethod("GET").WithPort(nat.Port("8080")).WithStartupTimeout(time.Second * 90),
			Env:          env,
			Networks: []string{
				networkName,
			},
			Cmd: cmd,
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

func TestBackend_RealmAccessViaSpecificRealm(t *testing.T) {

	keycloakContainerEnvVars := map[string]string{
		"KEYCLOAK_ADMIN":          "admin",
		"KEYCLOAK_ADMIN_PASSWORD": "admin",
	}
	keycloakBasePath := ""
	keyloakLegacyContainerEnvVars := map[string]string{
		"KEYCLOAK_USER":     "admin",
		"KEYCLOAK_PASSWORD": "admin",
		"DB_VENDOR":         "H2",
	}
	keycloakLegacyBasePath := "/auth"
	type test struct {
		keycloakImage string
		cmd           []string
		envVars       map[string]string
		basePath      string
	}

	tests := []test{
		{
			keycloakImage: "quay.io/keycloak/keycloak:21.1.1",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},

		//legacy
		{
			keycloakImage: "jboss/keycloak:16.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
		{
			keycloakImage: "jboss/keycloak:15.1.1",
			envVars:       keyloakLegacyContainerEnvVars,
			basePath:      keycloakLegacyBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			b, _ := Factory(context.Background(), logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, tfSpecificRealmClientSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()

			logicaltest.Test(t, logicaltest.TestCase{
				PreCheck:       testAccPreCheckFunc(t, server_url),
				LogicalBackend: b,
				Steps: []logicaltest.TestStep{
					testAccStepConfigForRealm(t, server_url, specificRealm, vaultClientId, vaultClientSecret),
					testAccStepReadConfigForRealm(t, server_url, specificRealm, vaultClientId, vaultClientSecret),
					testAccStepReadRealmClientSecret(t, specificRealm, "some-client", "some-client-secret123", fmt.Sprintf("%s%s", server_url, "/realms/realm-a")),
					testAccStepConfigDelete(t),
				},
			})
		})
	}

}
