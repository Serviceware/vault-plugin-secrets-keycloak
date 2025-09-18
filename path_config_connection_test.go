package keycloak

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloak"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

type DummyMockClients struct {
	realm         string
	client_id     string
	client_secret string
}

func mockedGocloakFactory(t *testing.T, realm, client_id, client_secret string) keycloak.ServiceFactoryFunc {
	t.Helper()
	return mockedGocloakFactoryWithDummys(t, DummyMockClients{
		realm:         realm,
		client_id:     client_id,
		client_secret: client_secret,
	})
}
func mockedGocloakFactoryWithDummys(t *testing.T, mockDummyClients ...DummyMockClients) keycloak.ServiceFactoryFunc {
	t.Helper()

	gocloakClientMock := &keycloak.MockedKeycloakService{}

	for _, dummyClient := range mockDummyClients {
		gocloakClientMock.On("LoginClient", mock.Anything, dummyClient.client_id, dummyClient.client_secret, dummyClient.realm).Return(&keycloak.JWT{
			AccessToken: "access123",
		}, nil)

		idOfRequestedClient := "internalClientId123"
		gocloakClientMock.On("GetClients", mock.Anything, "access123", dummyClient.realm, keycloak.GetClientsParams{
			ClientID: &dummyClient.client_id,
		}).Return([]*keycloak.Client{
			{
				ID: &idOfRequestedClient,
			},
		}, nil)

		gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", realm, idOfRequestedClient).Return(&keycloak.CredentialRepresentation{
			Value: &dummyClient.client_secret,
		}, nil)
	}

	return keycloak.NewMockedServiceFactoryFunc(gocloakClientMock)
}
func failingMockedGocloakFactory(t *testing.T) keycloak.ServiceFactoryFunc {
	t.Helper()

	gocloakClientMock := &keycloak.MockedKeycloakService{}

	gocloakClientMock.On("LoginClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("something went wrong"))

	return keycloak.NewMockedServiceFactoryFunc(gocloakClientMock)

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
func TestBackend_ConfigConnectionFailsNotIfNotConnectableAndSetToIgnore(t *testing.T) {
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
		"server_url":                "http://auth.example.com",
		"realm":                     "master",
		"client_id":                 "vault",
		"client_secret":             "wrong_secret",
		"ignore_connectivity_check": true,
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("Expected no error")
	}
	if resp.IsError() {
		t.Fatalf("bad: resp: %#v is an error\nerr:%s", resp, err)
	}

}
func TestBackend_UpdateConfigConnectionForRealm(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "realm1", "vault1", "realm1_secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"server_url":    "http://auth1.example.com",
		"client_id":     "vault1",
		"client_secret": "realm1_secret123",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/realms/realm1/connection",
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

	actualConfig, err := readConfigForKey(context.Background(), config.StorageView, "config/realms/realm1/connection")
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig := ConnectionConfig{
		ServerUrl:    "http://auth1.example.com",
		Realm:        "realm1",
		ClientId:     "vault1",
		ClientSecret: "realm1_secret123",
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}

func TestBackend_ConfigConnectionForRealmFailsIfNotConnectable(t *testing.T) {
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
		"server_url":    "http://auth1.example.com",
		"client_id":     "vault1",
		"client_secret": "...wrong_secret...",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/realms/realm1/connection",
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
func TestBackend_ConfigConnectionForRealmFailsNotIfNotConnectableAndSetToIgnore(t *testing.T) {
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
		"server_url":                "http://auth1.example.com",
		"client_id":                 "vault1",
		"client_secret":             "...wrong_secret...",
		"ignore_connectivity_check": true,
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/realms/realm1/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil {
		t.Fatalf("Expected no error")
	}
	if resp.IsError() {
		t.Fatalf("bad: resp: %#v is an error\nerr:%s", resp, err)
	}

}
func TestBackend_UpdateConfigConnectionForRealmDoNotConflict(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactoryWithDummys(t, DummyMockClients{
		realm:         "realm1",
		client_id:     "vault1",
		client_secret: "realm1_secret123",
	}, DummyMockClients{
		realm:         "realm2",
		client_id:     "vault2",
		client_secret: "realm2_secret456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configReq1 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/realms/realm1/connection",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":    "http://auth1.example.com",
			"client_id":     "vault1",
			"client_secret": "realm1_secret123",
		},
	}
	configReq2 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/realms/realm2/connection",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":    "http://auth2.example.com",
			"client_id":     "vault2",
			"client_secret": "realm2_secret456",
		},
	}
	resp, err = b.HandleRequest(context.Background(), configReq1)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}
	resp, err = b.HandleRequest(context.Background(), configReq2)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}
	actualConfig1, err := readConfigForKey(context.Background(), config.StorageView, "config/realms/realm1/connection")
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig1 := ConnectionConfig{
		ServerUrl:    "http://auth1.example.com",
		Realm:        "realm1",
		ClientId:     "vault1",
		ClientSecret: "realm1_secret123",
	}

	if !reflect.DeepEqual(actualConfig1, expectedConfig1) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig1, actualConfig1)
	}

	actualConfig2, err := readConfigForKey(context.Background(), config.StorageView, "config/realms/realm2/connection")
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig2 := ConnectionConfig{
		ServerUrl:    "http://auth2.example.com",
		Realm:        "realm2",
		ClientId:     "vault2",
		ClientSecret: "realm2_secret456",
	}

	if !reflect.DeepEqual(actualConfig2, expectedConfig2) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig2, actualConfig2)
	}
}

func TestBackend_DeleteConfigConnectionForRealm(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "realm1", "vault1", "realm1_secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	currentConfig := ConnectionConfig{
		ServerUrl:    "http://auth1.example.com",
		Realm:        "realm1",
		ClientId:     "vault1",
		ClientSecret: "realm1_secret123",
	}

	if err = writeConfigForKey(context.Background(), config.StorageView, currentConfig, "config/realms/realm1/connection"); err != nil {
		t.Fatal(err)
	}

	configReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/realms/realm1/connection",
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

func TestBackend_ReadConfigConnectionForRealm(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)
	b.KeycloakServiceFactory = mockedGocloakFactory(t, "realm1", "vault1", "realm1_secret123")
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	connectionConfig := ConnectionConfig{
		ServerUrl:    "http://auth1.example.com",
		Realm:        "realm1",
		ClientId:     "vault1",
		ClientSecret: "realm1_secret123",
	}

	if err = writeConfigForKey(context.Background(), config.StorageView, connectionConfig, "config/realms/realm1/connection"); err != nil {
		t.Fatal(err)
	}

	configReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/realms/realm1/connection",
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
		"server_url":    "http://auth1.example.com",
		"realm":         "realm1",
		"client_id":     "vault1",
		"client_secret": "realm1_secret123",
	}

	if !reflect.DeepEqual(resp.Data, expectedConfigData) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfigData, resp.Data)
	}
}
