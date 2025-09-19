package keycloak

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockServiceFactoryFunc creates a new [ServiceFactoryFunc] that always
// returns service.
func MockServiceFactoryFunc(service Service) ServiceFactoryFunc {
	return func(_ context.Context, _ string) (Service, error) {
		return service, nil
	}
}

// MockService implements [Service] by delegating function calls to
// [MockService.Mock].
type MockService struct {
	mock.Mock
}

func (m *MockService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error) {
	args := m.Called(ctx, clientID, clientSecret, realm)
	var t *JWT = nil
	if args.Get(0) != nil {
		t = args.Get(0).(*JWT)
	}
	return t, args.Error(1)
}
func (m *MockService) GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error) {
	args := m.Called(ctx, token, realm, params)
	return args.Get(0).([]*Client), args.Error(1)
}
func (m *MockService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error) {
	args := m.Called(ctx, token, realm, clientID)
	return args.Get(0).(*CredentialRepresentation), args.Error(1)
}
func (m *MockService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error) {
	args := m.Called(ctx, realm)
	return args.Get(0).(*WellKnownOpenidConfiguration), args.Error(1)
}
