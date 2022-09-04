package keycloak

import (
	"context"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v11"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	log "github.com/hashicorp/go-hclog"
)

type GoCloakFactory interface {
	NewClient(ctx context.Context, connConfig connectionConfig) (gocloak.GoCloak, error)
}

type backend struct {
	*framework.Backend

	GocloakFactory GoCloakFactory

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
	b.GocloakFactory = &DefaultGoCloakFactory{}
	b.logger = conf.Logger
	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		pathConfigConnection(b),
		pathClientSecret(b),
	}
}

type DefaultGoCloakFactory struct {
}

func (b *DefaultGoCloakFactory) NewClient(ctx context.Context, connConfig connectionConfig) (gocloak.GoCloak, error) {

	gocloakClient := gocloak.NewClient(connConfig.ServerUrl)

	if connConfig.BasePath != "" {
		basePrefix := strings.TrimPrefix(connConfig.BasePath, "/")
		if strings.HasPrefix(basePrefix, "/") {
			return nil, fmt.Errorf("base Path has invalid form (%s)", connConfig.BasePath)
		}

		adminRealmsBasePath := fmt.Sprintf("%sadmin/realms", basePrefix)
		realmsBasePath := fmt.Sprintf("%srealms", basePrefix)

		gocloakClient = gocloak.NewClient(connConfig.ServerUrl, gocloak.SetAuthAdminRealms(adminRealmsBasePath), gocloak.SetAuthRealms(realmsBasePath))
	}

	return gocloakClient, nil
}

const keycloakHelp = `
The Keycloak backend is retrieves secrets from keycloak.
`
