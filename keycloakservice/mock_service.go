package keycloakservice

import (
	"context"

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
func (m *MockedKeycloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error) {
	args := m.Called(ctx, clientID, clientSecret, realm)
	var t *JWT = nil
	if args.Get(0) != nil {
		t = args.Get(0).(*JWT)
	}
	return t, args.Error(1)
}
func (m *MockedKeycloakService) GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error) {
	args := m.Called(ctx, token, realm, params)
	return args.Get(0).([]*Client), args.Error(1)
}
func (m *MockedKeycloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error) {
	args := m.Called(ctx, token, realm, clientID)
	return args.Get(0).(*CredentialRepresentation), args.Error(1)
}

func (m *MockedKeycloakService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error) {
	args := m.Called(ctx, realm)
	return args.Get(0).(*WellKnownOpenidConfiguration), args.Error(1)
}

func (m *MockedKeycloakServiceFactory) NewClient(ctx context.Context, connConfig ConnectionConfig) (KeycloakService, error) {

	return m.MockedService, nil

}
