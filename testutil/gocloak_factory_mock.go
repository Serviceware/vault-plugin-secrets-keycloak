package testutil

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloakservice"
	"github.com/stretchr/testify/mock"
)

type MockedKeycloakServiceFactory struct {
	MockedService *MockedKeycloakService
}
type MockedKeycloakService struct {
	mock.Mock
}

func NewMockedKeycloakServiceFactory(service *MockedKeycloakService) *MockedKeycloakServiceFactory {
	return &MockedKeycloakServiceFactory{
		MockedService: service,
	}
}

// mock implementation of KeycloakService
func (m *MockedKeycloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*gocloak.JWT, error) {
	args := m.Called(ctx, clientID, clientSecret, realm)
	var t *gocloak.JWT = nil
	if args.Get(0) != nil {
		t = args.Get(0).(*gocloak.JWT)
	}
	return t, args.Error(1)
}
func (m *MockedKeycloakService) GetClients(ctx context.Context, token string, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	args := m.Called(ctx, token, realm, params)
	return args.Get(0).([]*gocloak.Client), args.Error(1)
}
func (m *MockedKeycloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*gocloak.CredentialRepresentation, error) {
	args := m.Called(ctx, token, realm, clientID)
	return args.Get(0).(*gocloak.CredentialRepresentation), args.Error(1)
}

func (m *MockedKeycloakServiceFactory) NewClient(ctx context.Context, connConfig keycloakservice.ConnectionConfig) (keycloakservice.KeycloakService, error) {

	return m.MockedService, nil

}
