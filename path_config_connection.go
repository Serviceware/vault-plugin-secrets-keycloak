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
			"base_path": {
				Type:        framework.TypeString,
				Description: `The base path if that is used e.g. "/" for new quarkus distro, or "/auth" for pre quarkus versions. If left empty ("") "/auth" is used. `,
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
	basePath := data.Get("base_path").(string)

	config := connectionConfig{
		ServerUrl:    server_url,
		Realm:        realm,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		BasePath:     basePath,
	}
	secret, err := b.readClientSecret(ctx, clientId, config)
	if err != nil {
		b.logger.Info("failed to read keycloak", "error", err)
		return logical.ErrorResponse("failed to read keycloak"), err
	}
	if secret != clientSecret {
		b.logger.Info("the read secret from keycloak for client is different then the one provided. This is a very strange state", clientId)
		return logical.ErrorResponse("unexpected keycloak secret state"), nil
	}

	err = writeConfig(ctx, req.Storage, config)
	if err != nil {
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

	responseData := map[string]interface{}{
		"client_id":     config.ClientId,
		"client_secret": config.ClientSecret,
		"server_url":    config.ServerUrl,
		"realm":         config.Realm,
	}

	if config.BasePath != "" {
		responseData["base_path"] = config.BasePath
	}

	response := &logical.Response{
		Data: responseData,
	}
	return response, nil

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

func deleteConfig(ctx context.Context, storage logical.Storage) error {

	if err := storage.Delete(ctx, storageKey); err != nil {
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
	BasePath     string `json:"base_path"`
}
