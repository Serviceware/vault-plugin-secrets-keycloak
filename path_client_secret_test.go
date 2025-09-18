package keycloak

import (
	"context"
	"reflect"
	"testing"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloakservice"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/testutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
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

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloakservice.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloakservice.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloakservice.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloakservice.CredentialRepresentation{
		Value: &secretValue,
	}, nil)

	b.KeycloakServiceFactory = testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

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

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloakservice.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloakservice.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloakservice.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloakservice.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "somerealm").Return(&keycloakservice.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER",
	}, nil)

	b.KeycloakServiceFactory = testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

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
func TestBackend_ReadClientSecretWhenNotExists(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloakservice.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"

	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloakservice.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloakservice.Client{}, nil)

	b.KeycloakServiceFactory = testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

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

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&keycloakservice.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "another-realm", keycloakservice.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloakservice.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "another-realm", idOfRequestedClient).Return(&keycloakservice.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "another-realm").Return(&keycloakservice.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER_FROM_OTHER_REALM",
	}, nil)

	b.KeycloakServiceFactory = testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

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

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vaultforrealm", "vaultforrealm_secret123", "somerealm").Return(&keycloakservice.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", keycloakservice.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*keycloakservice.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&keycloakservice.CredentialRepresentation{
		Value: &secretValue,
	}, nil)
	gocloakClientMock.On("GetWellKnownOpenidConfiguration", mock.Anything, "somerealm").Return(&keycloakservice.WellKnownOpenidConfiguration{
		Issuer: "THIS_IS_THE_ISSUER",
	}, nil)

	b.KeycloakServiceFactory = testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

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
