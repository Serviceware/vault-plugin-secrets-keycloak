package keycloak

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Nerzal/gocloak/v8"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend

	gocloakClient gocloak.GoCloak
	lock          sync.RWMutex
}

var _ logical.Factory = Factory

// Factory configures and returns Keycloak backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
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

func newBackend() (*backend, error) {

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

	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		pathConfigConnection(b),
		pathClientSecret(b),
	}
}

func (b *backend) Client(ctx context.Context, s logical.Storage) (gocloak.GoCloak, error) {

	b.lock.RLock()

	// If we already have a client, return it
	if b.gocloakClient != nil {
		b.lock.RUnlock()
		return b.gocloakClient, nil
	}

	b.lock.RUnlock()
	// Otherwise, attempt to make connection
	connConfig, err := readConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	b.lock.Lock()
	defer b.lock.Unlock()
	// If the client was created during the lock switch, return it
	if b.gocloakClient != nil {
		return b.gocloakClient, nil
	}

	b.gocloakClient = gocloak.NewClient(connConfig.ServerUrl)

	return b.gocloakClient, nil
}

const keycloakHelp = `
The Keycloak backend is retrieves secrets from keycloak.
`
