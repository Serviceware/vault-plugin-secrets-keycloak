package keycloak

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloakservice"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathClientSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "client-secret/" + framework.GenericNameRegex("clientId"),
		Fields: map[string]*framework.FieldSchema{
			"clientId": {
				Type:        framework.TypeString,
				Description: "Name of the client.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathClientSecretRead,
		},
	}
}
func (b *backend) pathClientSecretRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	clientId := d.Get("clientId").(string)
	if clientId == "" {
		return logical.ErrorResponse("missing client"), nil
	}

	config, err := readConfig(ctx, req.Storage)

	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	clientSecret, err := b.readClientSecret(ctx, clientId, config)
	if err != nil {
		return logical.ErrorResponse("could not retrieve client secret"), err
	}

	// Generate the response
	issuerUrl := config.ServerUrl + "/realms/" + config.Realm
	response := &logical.Response{
		Data: map[string]interface{}{
			"client_secret": clientSecret,
			"client_id":     clientId,
			"issuer_url":    issuerUrl,
		},
	}

	return response, nil
}

func (b *backend) readClientSecret(ctx context.Context, clientId string, config ConnectionConfig) (string, error) {

	return b.readClientSecretOfRealm(ctx, config.Realm, clientId, config)
}
func (b *backend) readClientSecretOfRealm(ctx context.Context, realm string, clientId string, config ConnectionConfig) (string, error) {

	goclaokClient, token, err := b.getClientAndAccessToken(ctx, config)
	if err != nil {
		return "", err
	}

	clients, err := goclaokClient.GetClients(ctx, token.AccessToken, realm, gocloak.GetClientsParams{
		ClientID: &clientId,
	})
	if err != nil {
		return "", err
	}
	if len(clients) != 1 {
		return "", fmt.Errorf("found %d clients for %s", len(clients), clientId)
	}

	client := clients[0]

	creds, err := goclaokClient.GetClientSecret(ctx, token.AccessToken, realm, *client.ID)

	if err != nil {
		return "", err
	}

	return *creds.Value, nil
}

func (b *backend) getClientAndAccessToken(ctx context.Context, config ConnectionConfig) (keycloakservice.KeycloakService, *gocloak.JWT, error) {
	goclaokClient, err := b.KeycloakServiceFactory.NewClient(ctx, keycloakservice.ConnectionConfig(config))

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create keycloak client: %w", err)
	}

	token, err := goclaokClient.LoginClient(ctx, config.ClientId, config.ClientSecret, config.Realm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to login: %w", err)
	}
	return goclaokClient, token, nil
}

func pathRealmClientSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "realm/" + framework.GenericNameRegex("realm") + "/client-secret/" + framework.GenericNameRegex("clientId"),
		Fields: map[string]*framework.FieldSchema{
			"clientId": {
				Type:        framework.TypeString,
				Description: "Name of the client.",
			},
			"realm": {
				Type:        framework.TypeString,
				Description: "Name of the realm.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRealmClientSecretRead,
		},
	}
}
func (b *backend) pathRealmClientSecretRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	realm := d.Get("realm").(string)
	if realm == "" {
		return logical.ErrorResponse("missing realm"), nil
	}
	clientId := d.Get("clientId").(string)
	if clientId == "" {
		return logical.ErrorResponse("missing client"), nil
	}

	config, err := readConfig(ctx, req.Storage)

	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}

	clientSecret, err := b.readClientSecretOfRealm(ctx, realm, clientId, config)
	if err != nil {
		return logical.ErrorResponse("could not retrieve client secret"), err
	}

	// Generate the response
	issuerUrl := config.ServerUrl + "/realms/" + realm
	response := &logical.Response{
		Data: map[string]interface{}{
			"client_secret": clientSecret,
			"client_id":     clientId,
			"issuer_url":    issuerUrl,
		},
	}

	return response, nil
}
