package keycloak

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v11"
	"github.com/docker/go-connections/nat"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// inspired by https://github.com/hashicorp/vault/blob/main/builtin/logical/rabbitmq/backend_test.go

func prepareKeycloakTestContainerWithVaultClient(t *testing.T) (func(), string, string, string, string) {

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

	cleanup, server_url, realm, client_id, client_secret := prepareKeycloakTestContainerWithVaultClient(t)
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

func prepareKeycloakTestContainer(t *testing.T, image string, env map[string]string, cmd []string, waitPath string) (func(), string, string) {

	t.Helper()

	if waitPath == "" {
		waitPath = "/"
	}
	realm := "master"

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP(waitPath).WithMethod("GET").WithPort(nat.Port("8080")).WithStartupTimeout(time.Second * 90),
		Env:          env,
		Cmd:          cmd,
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

	//serverUrl := "http://localhost:8080"
	return func() {
		defer keycloakC.Terminate(ctx)
	}, serverUrl, realm
}

func TestDefaultGoCloakFactory_NewClient(t *testing.T) {
	type args struct {
		ctx      context.Context
		basePath string
		image    string
		env      map[string]string
		cmd      []string
		waitPath string
	}
	tests := []struct {
		name    string
		b       *DefaultGoCloakFactory
		args    args
		want    gocloak.GoCloak
		wantErr bool
	}{
		{
			name: "Test with classic keycloak and empty base path",
			b:    &DefaultGoCloakFactory{},
			args: args{
				ctx: context.Background(),

				image: "quay.io/keycloak/keycloak:15.1.1",
				env: map[string]string{
					"KEYCLOAK_USER":     "admin",
					"KEYCLOAK_PASSWORD": "admin",
					"DB_VENDOR":         "h2",
				},
			},
		},
		{
			name: "Test with classic keycloak and explicit auth/",
			b:    &DefaultGoCloakFactory{},
			args: args{
				ctx:      context.Background(),
				basePath: "auth/",
				image:    "quay.io/keycloak/keycloak:15.1.1",
				env: map[string]string{
					"KEYCLOAK_USER":     "admin",
					"KEYCLOAK_PASSWORD": "admin",
					"DB_VENDOR":         "h2",
				},
			},
		},
		{
			name: "Test with quarkus keycloak",
			b:    &DefaultGoCloakFactory{},
			args: args{
				ctx:      context.Background(),
				basePath: "/",
				image:    "quay.io/keycloak/keycloak:19.0.1",
				env: map[string]string{
					"KEYCLOAK_ADMIN":          "admin",
					"KEYCLOAK_ADMIN_PASSWORD": "admin",
				},
				cmd: []string{"start-dev"},
			},
		},
		{
			name: "Works with some other base path",
			b:    &DefaultGoCloakFactory{},
			args: args{
				ctx:      context.Background(),
				basePath: "some/thing/other/",
				image:    "quay.io/keycloak/keycloak:19.0.1",
				env: map[string]string{
					"KEYCLOAK_ADMIN":          "admin",
					"KEYCLOAK_ADMIN_PASSWORD": "admin",
					"KC_HTTP_RELATIVE_PATH":   "some/thing/other",
				},
				cmd:      []string{"start-dev"},
				waitPath: "/some/thing/other",
			},
		},
		{
			name: "Raisese error if starts with double slash",
			b:    &DefaultGoCloakFactory{},
			args: args{
				ctx:      context.Background(),
				basePath: "//",
				image:    "quay.io/keycloak/keycloak:19.0.1",
				env: map[string]string{
					"KEYCLOAK_ADMIN":          "admin",
					"KEYCLOAK_ADMIN_PASSWORD": "admin",
				},
				cmd: []string{"start-dev"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cleanup, server_url, realm := prepareKeycloakTestContainer(t, tt.args.image, tt.args.env, tt.args.cmd, tt.args.waitPath)
			defer cleanup()

			b := &DefaultGoCloakFactory{}

			connConfig := connectionConfig{
				ServerUrl:    server_url,
				Realm:        realm,
				ClientId:     "...",
				ClientSecret: "...",
				BasePath:     tt.args.basePath,
			}
			got, err := b.NewClient(tt.args.ctx, connConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("DefaultGoCloakFactory.NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = got.Login(tt.args.ctx, "admin-cli", "", "master", "admin", "admin")

			if err != nil {
				t.Errorf("Login failed error = %v", err)

			}

		})
	}
}
