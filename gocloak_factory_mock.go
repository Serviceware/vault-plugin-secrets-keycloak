package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v8"
	"github.com/stretchr/testify/mock"
)

type MockedGocloakFactory struct {
	mock.Mock
}

func (m *MockedGocloakFactory) NewClient(ctx context.Context, connConfig connectionConfig) (gocloak.GoCloak, error) {

	args := m.Called(ctx, connConfig)
	return args.Get(0).(gocloak.GoCloak), args.Error(1)

}
