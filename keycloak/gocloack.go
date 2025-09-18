package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
)

// NewGocloackClient is compatible with [ServiceFactoryFunc] and creates a [Service] instance
// by wrapping [gocloak.NewClient].
func NewGocloackClient(ctx context.Context, connConfig ConnectionConfig) (Service, error) {
	gocloakClient := gocloak.NewClient(connConfig.ServerUrl)

	return &GoCloakBasedKeycloakService{
		serverUrl:     connConfig.ServerUrl,
		gocloakClient: gocloakClient,
	}, nil
}

// GoCloakBasedKeycloakService implements [Service] through the [gocloak] package.
type GoCloakBasedKeycloakService struct {
	serverUrl     string
	gocloakClient *gocloak.GoCloak
}

func (g *GoCloakBasedKeycloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error) {
	jwt, err := g.gocloakClient.LoginClient(ctx, clientID, clientSecret, realm)
	return (*JWT)(jwt), err
}

func (g *GoCloakBasedKeycloakService) GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error) {
	goCloakClients, err := g.gocloakClient.GetClients(ctx, token, realm, gocloak.GetClientsParams(params))
	if err != nil {
		return nil, err
	}

	clients := make([]*Client, len(goCloakClients))
	for i, client := range goCloakClients {
		clients[i] = (*Client)(client)
	}

	return clients, nil
}

func (g *GoCloakBasedKeycloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error) {
	credentials, err := g.gocloakClient.GetClientSecret(ctx, token, realm, clientID)
	return (*CredentialRepresentation)(credentials), err
}

func (g *GoCloakBasedKeycloakService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error) {

	res, err := http.Get(fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", g.serverUrl, realm))

	if err != nil {
		return nil, err
	}
	config := &WellKnownOpenidConfiguration{}
	err = json.NewDecoder(res.Body).Decode(config)

	if err != nil {
		return nil, err
	}
	return config, nil
}
