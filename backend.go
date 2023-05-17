package keycloak

import (
	"context"
	"fmt"
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
		pathClientSecret(b),
	}
}

type GoCloakFactory struct {
}

func (b *GoCloakFactory) NewClient(ctx context.Context, connConfig keycloakservice.ConnectionConfig) (keycloakservice.KeycloakService, error) {

	gocloakClient := gocloak.NewClient(connConfig.ServerUrl)

	return gocloakClient, nil
}

const keycloakHelp = `
The Keycloak backend is retrieves secrets from keycloak.
`
