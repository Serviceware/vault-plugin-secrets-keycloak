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
			logical.ReadOperation:   b.pathConnectionRead,
			logical.DeleteOperation: b.pathConnectionDelete,
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

	config := ConnectionConfig{
		ServerUrl:    server_url,
		Realm:        realm,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}

	if _, _, err := b.getClientAndAccessToken(ctx, config); err != nil {
		b.logger.Info("failed to access keycloak", "error", err)
		return logical.ErrorResponse("failed to access keycloak"), err
	}

	if err := writeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	return nil, nil
}
func (b *backend) pathConnectionDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	err := deleteConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConnectionRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"client_id":     config.ClientId,
			"client_secret": config.ClientSecret,
			"server_url":    config.ServerUrl,
			"realm":         config.Realm,
		},
	}
	return response, nil

}

func readConfig(ctx context.Context, storage logical.Storage) (ConnectionConfig, error) {
	entry, err := storage.Get(ctx, storageKey)
	if err != nil {
		return ConnectionConfig{}, err
	}
	if entry == nil {
		return ConnectionConfig{}, nil
	}

	var connConfig ConnectionConfig
	if err := entry.DecodeJSON(&connConfig); err != nil {
		return ConnectionConfig{}, err
	}
	return connConfig, nil
}

func writeConfig(ctx context.Context, storage logical.Storage, config ConnectionConfig) error {
	entry, err := logical.StorageEntryJSON(storageKey, config)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func deleteConfig(ctx context.Context, storage logical.Storage) error {

	if err := storage.Delete(ctx, storageKey); err != nil {
		return err
	}
	return nil
}

// ConnectionConfig contains the information required to make a connection to a RabbitMQ node
type ConnectionConfig struct {
	ServerUrl    string `json:"server_url"`
	Realm        string `json:"realm"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
