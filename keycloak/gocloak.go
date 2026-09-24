package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

// wellKnownHTTPClient is used to fetch the OpenID configuration. The timeout bounds requests whose context has no deadline.
var wellKnownHTTPClient = &http.Client{Timeout: 10 * time.Second}

// NewGocloakClient is compatible with [ServiceFactoryFunc] and creates a [Service] instance
// by wrapping [gocloak.NewClient].
func NewGocloakClient(serverUrl string) Service {
	gocloakClient := gocloak.NewClient(serverUrl)

	return &GocloakService{
		serverUrl:     serverUrl,
		gocloakClient: gocloakClient,
	}
}

// GocloakService implements [Service] through the [gocloak] package.
type GocloakService struct {
	serverUrl     string
	gocloakClient *gocloak.GoCloak
}

func (g *GocloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error) {
	jwt, err := g.gocloakClient.LoginClient(ctx, clientID, clientSecret, realm)
	if err != nil {
		return nil, translateGocloakError(err)
	}
	return (*JWT)(jwt), nil
}

func (g *GocloakService) GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error) {
	goCloakClients, err := g.gocloakClient.GetClients(ctx, token, realm, gocloak.GetClientsParams(params))
	if err != nil {
		return nil, translateGocloakError(err)
	}

	clients := make([]*Client, len(goCloakClients))
	for i, client := range goCloakClients {
		clients[i] = (*Client)(client)
	}

	return clients, nil
}

func (g *GocloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error) {
	credentials, err := g.gocloakClient.GetClientSecret(ctx, token, realm, clientID)
	if err != nil {
		return nil, translateGocloakError(err)
	}
	return (*CredentialRepresentation)(credentials), nil
}

func (g *GocloakService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error) {
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", g.serverUrl, realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := wellKnownHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, &HTTPStatusError{StatusCode: res.StatusCode, URL: url}
	}

	config := &WellKnownOpenidConfiguration{}
	if err = json.NewDecoder(res.Body).Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}
