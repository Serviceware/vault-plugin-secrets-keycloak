package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloakservice"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	log "github.com/hashicorp/go-hclog"
)

type backend struct {
	*framework.Backend

	KeycloakServiceFactory keycloakservice.KeycloakServiceFactory

	logger log.Logger
}

var _ logical.Factory = Factory

// Factory configures and returns Keycloak backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend(conf)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend(conf *logical.BackendConfig) (*backend, error) {

	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(keycloakHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/connection",
			},
		},

		Paths: framework.PathAppend(
			b.paths(),
		),
	}
	b.KeycloakServiceFactory = &GoCloakFactory{}
	b.logger = conf.Logger
	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		pathConfigConnection(b),
		pathClientSecretDeprecated(b),
		pathClientSecret(b),
		pathRealmClientSecret(b),
	}
}

type GoCloakFactory struct {
}

type GoCloakBasedKeycloakService struct {
	serverUrl     string
	gocloakClient *gocloak.GoCloak
}

// implement KeycloakService and delegate methods to gocloakClient
func (g *GoCloakBasedKeycloakService) LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*gocloak.JWT, error) {
	return g.gocloakClient.LoginClient(ctx, clientID, clientSecret, realm)
}

func (g *GoCloakBasedKeycloakService) GetClients(ctx context.Context, token string, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	return g.gocloakClient.GetClients(ctx, token, realm, params)
}
func (g *GoCloakBasedKeycloakService) GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*gocloak.CredentialRepresentation, error) {
	return g.gocloakClient.GetClientSecret(ctx, token, realm, clientID)
}
func (g *GoCloakBasedKeycloakService) GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*keycloakservice.WellKnownOpenidConfiguration, error) {

	res, err := http.Get(fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", g.serverUrl, realm))

	if err != nil {
		return nil, err
	}
	config := &keycloakservice.WellKnownOpenidConfiguration{}
	err = json.NewDecoder(res.Body).Decode(config)

	if err != nil {
		return nil, err
	}
	return config, nil
}

func (b *GoCloakFactory) NewClient(ctx context.Context, connConfig keycloakservice.ConnectionConfig) (keycloakservice.KeycloakService, error) {

	gocloakClient := gocloak.NewClient(connConfig.ServerUrl)

	return &GoCloakBasedKeycloakService{
		serverUrl:     connConfig.ServerUrl,
		gocloakClient: gocloakClient,
	}, nil
}

const keycloakHelp = `
The Keycloak backend is retrieves secrets from keycloak.
`
