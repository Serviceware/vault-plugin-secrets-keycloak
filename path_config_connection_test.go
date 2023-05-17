package keycloak

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/testutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

func mockedGocloakFactory(t *testing.T, realm, client_id, client_secret string) *testutil.MockedKeycloakServiceFactory {
	t.Helper()

	gocloakClientMock := &testutil.MockedKeycloakService{}
	gocloakClientMock.On("LoginClient", mock.Anything, client_id, client_secret, realm).Return(&gocloak.JWT{
		AccessToken: "access123",
	}, nil)

	idOfRequestedClient := "internalClientId123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", realm, gocloak.GetClientsParams{
		ClientID: &client_id,
	}).Return([]*gocloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)

	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", realm, idOfRequestedClient).Return(&gocloak.CredentialRepresentation{
		Value: &client_secret,
	}, nil)

	return testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)
}
func failingMockedGocloakFactory(t *testing.T) *testutil.MockedKeycloakServiceFactory {
	t.Helper()

	gocloakClientMock := &testutil.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("something went wrong"))

	return testutil.NewMockedKeycloakServiceFactory(gocloakClientMock)

}
func TestBackend_UpdateConfigConnection(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "master", "vault", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"server_url":    "http://auth.example.com",
		"realm":         "master",
		"client_id":     "vault",
		"client_secret": "secret123",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	actualConfig, err := readConfig(context.Background(), config.StorageView)
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig := ConnectionConfig{
		ServerUrl:    "http://auth.example.com",
		Realm:        "master",
		ClientId:     "vault",
		ClientSecret: "secret123",
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}
func TestBackend_DeleteConfigConnection(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "master", "vault", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	currentConfig := ConnectionConfig{
		ServerUrl:    "http://auth.example.com",
		Realm:        "master",
		ClientId:     "vault",
		ClientSecret: "secret123",
	}

	if err = writeConfig(context.Background(), config.StorageView, currentConfig); err != nil {
		t.Fatal(err)
	}

	configReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	expectedConfig := ConnectionConfig{
		ServerUrl:    "",
		Realm:        "",
		ClientId:     "",
		ClientSecret: "",
	}

	actualConfig, err := readConfig(context.Background(), config.StorageView)

	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}
	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}

func TestBackend_ReadConfigConnection(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "master", "vault", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	connectionConfig := ConnectionConfig{
		ServerUrl:    "http://auth.example.com",
		Realm:        "master",
		ClientId:     "vault",
		ClientSecret: "secret123",
	}

	if err = writeConfig(context.Background(), config.StorageView, connectionConfig); err != nil {
		t.Fatal(err)
	}

	configReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
	}

	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp == nil {
		t.Fatal("expected non nil response")
	}

	expectedConfigData := map[string]interface{}{
		"server_url":    "http://auth.example.com",
		"realm":         "master",
		"client_id":     "vault",
		"client_secret": "secret123",
	}

	if !reflect.DeepEqual(resp.Data, expectedConfigData) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfigData, resp.Data)
	}
}

func TestBackend_ConfigConnectionFailsIfNotConnectable(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = failingMockedGocloakFactory(t)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"server_url":    "http://auth.example.com",
		"realm":         "master",
		"client_id":     "vault",
		"client_secret": "wrong_secret",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err == nil {
		t.Fatalf("Expected error")
	}
	if !resp.IsError() {
		t.Fatalf("bad: resp: %#v is not an error\nerr:%s", resp, err)
	}

}
