package keycloak

import (
	"context"
	"reflect"
	"testing"

	"github.com/Nerzal/gocloak/v8"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/mocks"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

func TestBackend_ReadClientSecret(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(config)

	if err != nil {
		t.Fatal(err)
	}

	gocloakClientMock := &mocks.GoCloak{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&gocloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"
	idOfRequestedClient := "123"
	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", gocloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*gocloak.Client{
		{
			ID: &idOfRequestedClient,
		},
	}, nil)
	secretValue := "mysecret123"
	gocloakClientMock.On("GetClientSecret", mock.Anything, "access123", "somerealm", idOfRequestedClient).Return(&gocloak.CredentialRepresentation{
		Value: &secretValue,
	}, nil)

	mockFactory := new(MockedGocloakFactory)
	b.GocloakFactory = mockFactory
	mockFactory.On("NewClient", mock.Anything, mock.Anything).Return(gocloakClientMock, nil)

	writeConfig(context.Background(), config.StorageView, connectionConfig{
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

	gocloakClientMock := &mocks.GoCloak{}

	gocloakClientMock.On("LoginClient", mock.Anything, "vault", "secret123", "somerealm").Return(&gocloak.JWT{
		AccessToken: "access123",
	}, nil)

	requestedClientId := "myclient"

	gocloakClientMock.On("GetClients", mock.Anything, "access123", "somerealm", gocloak.GetClientsParams{
		ClientID: &requestedClientId,
	}).Return([]*gocloak.Client{}, nil)

	mockFactory := new(MockedGocloakFactory)
	b.GocloakFactory = mockFactory
	mockFactory.On("NewClient", mock.Anything, mock.Anything).Return(gocloakClientMock, nil)

	writeConfig(context.Background(), config.StorageView, connectionConfig{
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
	path := "client-secret/" + requestedClientId
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
