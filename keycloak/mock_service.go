package keycloak

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockedKeycloakServiceFactory implements [KeycloakServiceFactory] by always
// returning [MockedKeycloakServiceFactory.Service] from [MockedKeycloakServiceFactory.NewClient].
type MockedKeycloakServiceFactory struct {
	Service *MockedKeycloakService
}

// NewMockedServiceFactoryFunc creates a new [ServiceFactoryFunc].
func NewMockedServiceFactoryFunc(service *MockedKeycloakService) ServiceFactoryFunc {
	return func(ctx context.Context, connConfig ConnectionConfig) (Service, error) {
		return service, nil
	}
}

// MockedKeycloakService implements [Service] by delegating function
// calls to [MockedKeycloakService.Mock].
type MockedKeycloakService struct {
	mock.Mock
}

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
