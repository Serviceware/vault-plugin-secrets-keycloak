package keycloak

import (
	"context"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloak"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBackend_ReadClientSecretDeprecated(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &keycloak.MockService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloak.CredentialRepresentation{
		Value: &secretValue,
	}, nil)

	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(gocloakClientMock)

	writeConfig(context.Background(), config.StorageView, ConnectionConfig{
		ClientId:     "vault",
		ClientSecret: "secret123",
		Realm:        "somerealm",
		ServerUrl:    "http://example.com/auth",
	})

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	path := "client-secret/" + requestedClientId
	readClientSecretReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readClientSecretReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}

	expectedResponse := map[string]interface{}{
		"client_secret": "mysecret123",
		"client_id":     "myclient",
		"issuer_url":    "http://example.com/auth/realms/somerealm",
	}

	if !reflect.DeepEqual(resp.Data, expectedResponse) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedResponse, resp.Data)
	}
}
func TestBackend_ReadClientSecret(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &keycloak.MockService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloak.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "somerealm").Return(&keycloak.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER",
	}, nil)

	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(gocloakClientMock)

	writeConfig(context.Background(), config.StorageView, ConnectionConfig{
		ClientId:     "vault",
		ClientSecret: "secret123",
		Realm:        "somerealm",
		ServerUrl:    "http://example.com/auth",
	})

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	path := "clients/" + requestedClientId + "/secret"
	readClientSecretReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readClientSecretReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}

	expectedResponse := map[string]interface{}{
		"client_secret": "mysecret123",
		"client_id":     "myclient",
		"issuer":        "THIS_IS_THE_ISSUER",
	}

	if !reflect.DeepEqual(resp.Data, expectedResponse) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedResponse, resp.Data)
	}
}

func TestBackend_OnlyLoginWhenNecessary(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	err := writeConfig(t.Context(), config.StorageView, ConnectionConfig{
		ClientId:     "vault",
		ClientSecret: "secret123",
		Realm:        "somerealm",
		ServerUrl:    "http://example.com/auth",
	})
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Provide common mock setup elsewhere and use it here.
	requestedClientId := "myclient"
	makeMock := func(expiresIn time.Duration) *keycloak.MockService {
		gocloakClientMock := &keycloak.MockService{}
		gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(
			&keycloak.JWT{AccessToken: "access123",
				ExpiresIn: int(expiresIn / time.Second),
			}, nil)
		idOfRequestedClient := "123"
		gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloak.GetClientsParams{ClientID: &requestedClientId}).Return(
			[]*keycloak.Client{{ID: &idOfRequestedClient}}, nil)
		secretValue := "mysecret123"
		gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(
			&keycloak.CredentialRepresentation{Value: &secretValue}, nil)
		gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "somerealm").Return(
			&keycloak.WellKnownOpenidConfiguration{Issuer: "THIS_IS_THE_ISSUER"}, nil)
		return gocloakClientMock
	}

	tests := []struct {
		name                  string
		expiresIn             time.Duration
		waitDuration          time.Duration
		expectedNumberOfCalls int
	}{
		{name: "expired token", expiresIn: 0, expectedNumberOfCalls: 2},
		{name: "valid token", expiresIn: 60 * time.Second, expectedNumberOfCalls: 1},
		{name: "token expired after wait time", expiresIn: 60 * time.Second, waitDuration: 61 * time.Second, expectedNumberOfCalls: 2},
		{name: "token valid but above safety threshold", expiresIn: 60 * time.Second, waitDuration: 56 * time.Second, expectedNumberOfCalls: 2},
		{name: "token still valid after waiting", expiresIn: 60 * time.Second, waitDuration: 30 * time.Second, expectedNumberOfCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, err := newBackend(config)
				if err != nil {
					t.Fatal(err)
				}

				client := makeMock(test.expiresIn)
				b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(client)
				if err = b.Setup(t.Context(), config); err != nil {
					t.Fatal(err)
				}

				request := &logical.Request{
					Operation: logical.ReadOperation,
					Path:      "clients/" + requestedClientId + "/secret",
					Storage:   config.StorageView,
				}
				// First request: Expect login and retrieve a token as we do not have one, initially.
				resp, err := b.HandleRequest(t.Context(), request)
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError())

				time.Sleep(test.waitDuration)

				// Second request after sleeping:
				// Based on the concrete test case we might need to login again and request a new token.
				resp, err = b.HandleRequest(t.Context(), request)
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError())

				client.AssertNumberOfCalls(t, "LoginClient", test.expectedNumberOfCalls)
			})
		})
	}
}

func TestBackend_ReadClientSecretWhenNotExists(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &keycloak.MockService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"

	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloak.Client{}, nil)

	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(gocloakClientMock)

	writeConfig(context.Background(), config.StorageView, ConnectionConfig{
		ClientId:     "vault",
		ClientSecret: "secret123",
		Realm:        "somerealm",
	})

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	path := "clients/" + requestedClientId + "/secret"
	readClientSecretReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readClientSecretReq)
	if err == nil || (resp == nil || !resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}

}

func TestBackend_ReadClientSecretFromOtherRealm(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &keycloak.MockService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "another-realm", keycloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "another-realm", idOfRequestedClient).Return(&keycloak.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "another-realm").Return(&keycloak.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER_FROM_OTHER_REALM",
	}, nil)

	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(gocloakClientMock)

	writeConfig(context.Background(), config.StorageView, ConnectionConfig{
		ClientId:     "vault",
		ClientSecret: "secret123",
		Realm:        "somerealm",
		ServerUrl:    "http://example.com/auth",
	})

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	path := "realms/another-realm/clients/" + requestedClientId + "/secret"
	readClientSecretReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readClientSecretReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}

	expectedResponse := map[string]interface{}{
		"client_secret": "mysecret123",
		"client_id":     "myclient",
		"issuer":        "THIS_IS_THE_ISSUER_FROM_OTHER_REALM",
	}

	if !reflect.DeepEqual(resp.Data, expectedResponse) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedResponse, resp.Data)
	}
}

func TestBackend_ReadClientSecretForRealm(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &keycloak.MockService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vaultforrealm", "vaultforrealm_secret123", "somerealm").Return(&keycloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloak.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "somerealm").Return(&keycloak.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER",
	}, nil)

	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(gocloakClientMock)

	writeConfigForKey(context.Background(), config.StorageView, ConnectionConfig{
		ClientId:     "vaultforrealm",
		ClientSecret: "vaultforrealm_secret123",
		Realm:        "somerealm",
		ServerUrl:    "http://example.com/auth",
	}, "config/realms/somerealm/connection")

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	path := "realms/somerealm/clients/" + requestedClientId + "/secret"
	readClientSecretReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readClientSecretReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}

	expectedResponse := map[string]interface{}{
		"client_secret": "mysecret123",
		"client_id":     "myclient",
		"issuer":        "THIS_IS_THE_ISSUER",
	}

	if !reflect.DeepEqual(resp.Data, expectedResponse) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedResponse, resp.Data)
	}
}
