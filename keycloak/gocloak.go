package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
)

// NewGocloakClient is compatible with [ServiceFactoryFunc] and creates a [Service] instance
// by wrapping [gocloak.NewClient].
func NewGocloakClient(ctx context.Context, serverUrl string) (Service, error) {
	gocloakClient := gocloak.NewClient(serverUrl)

	return &GocloakService{
		serverUrl:     serverUrl,
		gocloakClient: gocloakClient,
	}, nil
}

// GocloakService implements [Service] through the [gocloak] package.
type GocloakService struct {
	serverUrl     string
	gocloakClient *gocloak.GoCloak
}

func (g *GocloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error) {
	jwt, err := g.gocloakClient.LoginClient(ctx, clientID, clientSecret, realm)
	return (*JWT)(jwt), err
}

func (g *GocloakService) GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error) {
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

func (g *GocloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error) {
	credentials, err := g.gocloakClient.GetClientSecret(ctx, token, realm, clientID)
	return (*CredentialRepresentation)(credentials), err
}

func (g *GocloakService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error) {
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
