package keycloak

import (
	"context"
	"fmt"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloak"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathClientSecretDeprecated(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "client-secret/" + framework.GenericNameRegex("clientId"),
		Fields: map[string]*framework.FieldSchema{
			"clientId": {
				Type:        framework.TypeString,
				Description: "Name of the client.",
			},
		},
		Deprecated: true,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathClientSecretReadDeprecated,
		},
	}
}
func (b *backend) pathClientSecretReadDeprecated(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
func pathClientSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "clients/" + framework.GenericNameRegex("clientId") + "/secret",
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

	openIdConifg, err := b.getGetWellKnownOpenidConfiguration(ctx, config, config.Realm)
	if err != nil {
		return logical.ErrorResponse("could not retrieve issuer"), err
	}

	// Generate the response
	response := &logical.Response{
		Data: map[string]interface{}{
			"client_secret": clientSecret,
			"client_id":     clientId,
			"issuer":        openIdConifg.Issuer,
		},
	}

	return response, nil
}

func (b *backend) getGetWellKnownOpenidConfiguration(ctx context.Context, config ConnectionConfig, realm string) (*keycloak.WellKnownOpenidConfiguration, error) {
	client := b.KeycloakServiceFactory(config.ServerUrl)
	return client.GetWellKnownOpenidConfiguration(ctx, realm)
}

func (b *backend) readClientSecret(ctx context.Context, clientId string, config ConnectionConfig) (string, error) {

	return b.readClientSecretOfRealm(ctx, config.Realm, clientId, config)
}
func (b *backend) readClientSecretOfRealm(ctx context.Context, realm string, clientId string, config ConnectionConfig) (string, error) {

	goclaokClient, token, err := b.getClientAndAccessToken(ctx, config)

	if err != nil {
		return "", err
	}

	clients, err := goclaokClient.GetClients(ctx, token.AccessToken, realm, keycloak.GetClientsParams{
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

func (b *backend) getClientAndAccessToken(ctx context.Context, config ConnectionConfig) (keycloak.Service, *keycloak.JWT, error) {
	goclaokClient := b.KeycloakServiceFactory(config.ServerUrl)

	token, err := goclaokClient.LoginClient(ctx, config.ClientId, config.ClientSecret, config.Realm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to login: %w", err)
	}
	return goclaokClient, token, nil
}

func pathRealmClientSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "realms/" + framework.GenericNameRegex("realm") + "/clients/" + framework.GenericNameRegex("clientId") + "/secret",
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

	config, err := readConfigForKey(ctx, req.Storage, fmt.Sprintf(storagePerRealmKey, realm))
	if err != nil {
		return logical.ErrorResponse("failed to read config"), err
	}
	// if config is empty, try to read the default config
	if config.ServerUrl == "" {
		config, err = readConfig(ctx, req.Storage)
		if err != nil {
			return logical.ErrorResponse("failed to read config"), err
		}

	}

	clientSecret, err := b.readClientSecretOfRealm(ctx, realm, clientId, config)
	if err != nil {
		return logical.ErrorResponse("could not retrieve client secret"), err
	}

	openidConfig, err := b.getGetWellKnownOpenidConfiguration(ctx, config, realm)
	if err != nil {
		return logical.ErrorResponse("could not retrieve issuer"), err
	}

	// Generate the response
	issuerUrl := openidConfig.Issuer
	response := &logical.Response{
		Data: map[string]interface{}{
			"client_secret": clientSecret,
			"client_id":     clientId,
			"issuer":        issuerUrl,
		},
	}

	return response, nil
}
