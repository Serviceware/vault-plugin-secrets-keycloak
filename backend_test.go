package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
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
	keyloak26ContainerEnvVars := map[string]string{
		"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
		"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
	}
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
		{
			keycloakImage: "quay.io/keycloak/keycloak:25.0",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},
		{
			keycloakImage: "quay.io/keycloak/keycloak:26.1",
			cmd:           []string{"start-dev"},
			envVars:       keyloak26ContainerEnvVars,
			basePath:      keycloakBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			context := context.Background()
			b, _ := Factory(context, logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, basicTfSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()

			s := &logical.InmemStorage{}
			testAccStepConfig(t, server_url, realm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadConfig(t, server_url, realm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadSecretDeprecated(t, vaultClientId, vaultClientSecret, b, s)
			testAccStepConfigDelete(t, b, s)
		})
	}
}

func TestBackend_MultiRealmAccess(t *testing.T) {

	keycloakContainerEnvVars := map[string]string{
		"KEYCLOAK_ADMIN":          "admin",
		"KEYCLOAK_ADMIN_PASSWORD": "admin",
	}
	keycloakBasePath := ""
	keyloak26ContainerEnvVars := map[string]string{
		"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
		"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
	}

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
		{
			keycloakImage: "quay.io/keycloak/keycloak:25.0",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},

		{
			keycloakImage: "quay.io/keycloak/keycloak:26.1",
			cmd:           []string{"start-dev"},
			envVars:       keyloak26ContainerEnvVars,
			basePath:      keycloakBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			context := context.Background()
			b, _ := Factory(context, logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, tfMultiRealmClientSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()
			s := &logical.InmemStorage{}

			testAccStepConfig(t, server_url, realm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadConfig(t, server_url, realm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadRealmClientSecret(t, "realm-a", "some-client", "some-client-secret123-in-realm-realm-a", fmt.Sprintf("%s%s", server_url, "/realms/realm-a"), b, s)
			testAccStepReadRealmClientSecret(t, "realm-b", "some-client", "some-client-secret123-in-realm-realm-b", fmt.Sprintf("%s%s", server_url, "/realms/realm-b"), b, s)
			testAccStepConfigDelete(t, b, s)

		})
	}

}

func testAccStepConfig(t *testing.T, server_url, realm, client_id, client_secret string, backend logical.Backend, storage logical.Storage) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data: map[string]interface{}{
			"server_url":    server_url,
			"realm":         realm,
			"client_id":     client_id,
			"client_secret": client_secret,
		},
		Storage: storage,
	}
	_, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

}

func testAccStepConfigForRealm(t *testing.T, server_url, realm, client_id, client_secret string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("config/realms/%s/connection", realm),
		Data: map[string]interface{}{
			"server_url":    server_url,
			"client_id":     client_id,
			"client_secret": client_secret,
		},
		Storage: storage,
	}
	_, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

}
func testAccStepConfigDelete(t *testing.T, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/connection",
		Storage:   storage,
	}
	_, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

}
func testAccStepReadConfig(t *testing.T, server_url, realm, client_id, client_secret string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/connection",

		Storage: storage,
	}
	res, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	var d struct {
		Realm        string `mapstructure:"realm"`
		ServerUrl    string `mapstructure:"server_url"`
		ClientId     string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}
	err = mapstructure.Decode(res.Data, &d)
	require.NoError(t, err, "should not error on decode")

	require.Equalf(t, client_secret, d.ClientSecret, "secret was not as expected: %s", d.ClientSecret)
	require.Equalf(t, client_id, d.ClientId, "id was not as expected: %s", d.ClientId)
	require.Equalf(t, server_url, d.ServerUrl, "server_url was not as expected: %s", d.ServerUrl)
	require.Equalf(t, realm, d.Realm, "secret was not as expected: %s", d.Realm)

}

func testAccStepReadConfigForRealm(t *testing.T, server_url, realm, client_id, client_secret string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("config/realms/%s/connection", realm),

		Storage: storage,
	}
	res, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	var d struct {
		Realm        string `mapstructure:"realm"`
		ServerUrl    string `mapstructure:"server_url"`
		ClientId     string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}
	err = mapstructure.Decode(res.Data, &d)
	require.NoError(t, err, "should not error on decode")

	require.Equalf(t, client_secret, d.ClientSecret, "secret was not as expected: %s", d.ClientSecret)
	require.Equalf(t, client_id, d.ClientId, "id was not as expected: %s", d.ClientId)
	require.Equalf(t, server_url, d.ServerUrl, "server_url was not as expected: %s", d.ServerUrl)
	require.Equalf(t, realm, d.Realm, "secret was not as expected: %s", d.Realm)

}

func testAccStepReadSecretDeprecated(t *testing.T, clientId string, expectedClientSecret string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("client-secret/%s", clientId),
		Storage:   storage,
	}
	res, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	var d struct {
		ClientSecret string `mapstructure:"client_secret"`
	}
	err = mapstructure.Decode(res.Data, &d)
	require.NoError(t, err, "should not error on decode")

}
func testAccStepReadRealmClientSecret(t *testing.T, realm string, clientId string, expectedClientSecret string, expectedIssuer string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("realms/%s/clients/%s/secret", realm, clientId),
		Storage:   storage,
	}
	res, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	var d struct {
		ClientSecret string `mapstructure:"client_secret"`
		ClientId     string `mapstructure:"client_id"`
		Issuer       string `mapstructure:"issuer"`
	}
	err = mapstructure.Decode(res.Data, &d)
	require.NoError(t, err, "should not error on decode")

	require.Equalf(t, expectedClientSecret, d.ClientSecret, "secret was not as expected: %s", d.ClientSecret)
	require.Equalf(t, clientId, d.ClientId, "id was not as expected: %s", d.ClientId)
	require.Equalf(t, expectedIssuer, d.Issuer, "issuer was not as expected: %s", d.Issuer)
}
func testAccStepReadRealmWellknownOpenIdConfig(t *testing.T, realm string, expectedIssuer string, backend logical.Backend, storage logical.Storage) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("realms/%s/openid-configuration", realm),
		Storage:   storage,
	}
	res, err := backend.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	var d struct {
		Issuer string `mapstructure:"issuer"`
	}
	err = mapstructure.Decode(res.Data, &d)
	require.NoError(t, err, "should not error on decode")

	require.Equalf(t, expectedIssuer, d.Issuer, "issuer was not as expected: %s", d.Issuer)

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
	keyloak26ContainerEnvVars := map[string]string{
		"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
		"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
	}
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
		{
			keycloakImage: "quay.io/keycloak/keycloak:25.0",
			cmd:           []string{"start-dev"},
			envVars:       keycloakContainerEnvVars,
			basePath:      keycloakBasePath,
		},
		{
			keycloakImage: "quay.io/keycloak/keycloak:26.1",
			cmd:           []string{"start-dev"},
			envVars:       keyloak26ContainerEnvVars,
			basePath:      keycloakBasePath,
		},
	}

	for _, test := range tests {
		t.Run(test.keycloakImage, func(t *testing.T) {

			context := context.Background()
			b, _ := Factory(context, logical.TestBackendConfig())

			cleanup, server_url := prepareKeycloakTestContainer(t, test.keycloakImage, tfSpecificRealmClientSetup, test.basePath, test.cmd, test.envVars)
			defer cleanup()

			s := &logical.InmemStorage{}
			testAccStepConfigForRealm(t, server_url, specificRealm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadConfigForRealm(t, server_url, specificRealm, vaultClientId, vaultClientSecret, b, s)
			testAccStepReadRealmClientSecret(t, specificRealm, "some-client", "some-client-secret123", fmt.Sprintf("%s%s", server_url, "/realms/specific-realm"), b, s)
			testAccStepConfigDelete(t, b, s)

		})
	}

}
