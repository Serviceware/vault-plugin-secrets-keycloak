package keycloak

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageKey = "config/connection"
)

func pathConfigConnection(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/connection",
		Fields: map[string]*framework.FieldSchema{
			"server_url": {
				Type:        framework.TypeString,
				Description: "Base Keycloak Url http://auth.example.org",
			},
			"realm": {
				Type:        framework.TypeString,
				Description: "Name of the realm where the clients are stored",
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "Client to be used to access keycloak",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: `The secret that is used to get an access token`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConnectionUpdate,
		},
	}
}

func (b *backend) pathConnectionUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	server_url := data.Get("server_url").(string)
	if server_url == "" {
		return logical.ErrorResponse("missing server_url"), nil
	}

	realm := data.Get("realm").(string)
	if realm == "" {
		return logical.ErrorResponse("missing realm"), nil
	}

	clientId := data.Get("client_id").(string)
	if clientId == "" {
		return logical.ErrorResponse("missing client_id"), nil
	}
	clientSecret := data.Get("client_secret").(string)
	if clientSecret == "" {
		return logical.ErrorResponse("missing client_secret"), nil
	}

	// Store it
	config := connectionConfig{
		ServerUrl:    server_url,
		Realm:        realm,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}
	err := writeConfig(ctx, req.Storage, config)
	if err != nil {
		return nil, err
	}

	// Reset the client connection
	///b.resetClient(ctx) TODO: should we?

	return nil, nil
}

func readConfig(ctx context.Context, storage logical.Storage) (connectionConfig, error) {
	entry, err := storage.Get(ctx, storageKey)
	if err != nil {
		return connectionConfig{}, err
	}
	if entry == nil {
		return connectionConfig{}, nil
	}

	var connConfig connectionConfig
	if err := entry.DecodeJSON(&connConfig); err != nil {
		return connectionConfig{}, err
	}
	return connConfig, nil
}

func writeConfig(ctx context.Context, storage logical.Storage, config connectionConfig) error {
	entry, err := logical.StorageEntryJSON(storageKey, config)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

// connectionConfig contains the information required to make a connection to a RabbitMQ node
type connectionConfig struct {
	ServerUrl    string `json:"server_url"`
	Realm        string `json:"realm"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
