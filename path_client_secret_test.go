package keycloak

import (
	"context"
	"reflect"
	"testing"

	"github.com/Nerzal/gocloak/v8"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

type MockedKeycloakClient struct {
	mock.Mock
}

func (m *MockedKeycloakClient) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*gocloak.JWT, error) {
	args := m.Called(ctx, clientID, clientSecret, realm)
	return args.Get(0).(*gocloak.JWT), args.Error(1)
}
func (m *MockedKeycloakClient) GetClients(ctx context.Context, accessToken, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	args := m.Called(ctx, accessToken, realm, params)
	var clients *[]gocloak.Client
	clients = args.Get(0).(*[]gocloak.Client)
	return clients, args.Error(1)
}
func (m *MockedKeycloakClient) GetClientSecret(ctx context.Context, token, realm, clientID string) (*gocloak.CredentialRepresentation, error) {
	args := m.Called(ctx, token, realm, clientID)
	return args.Get(0).(*gocloak.CredentialRepresentation), args.Error(1)
}
func TestBackend_ReadClientSecret(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend()
	mockClient := new(MockedKeycloakClient)
	b.gocloakClient = mockClient

	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "client-secret/myclient",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
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
