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
	issuerUrl := config.ServerUrl + "/auth/realms/" + config.Realm
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

	goclaokClient, err := b.KeycloakServiceFactory.NewClient(ctx, keycloakservice.ConnectionConfig(config))

	if err != nil {
		return "", err
	}

	token, err := goclaokClient.LoginClient(ctx, config.ClientId, config.ClientSecret, config.Realm)
	if err != nil {
		return "", err
	}

	clients, err := goclaokClient.GetClients(ctx, token.AccessToken, config.Realm, gocloak.GetClientsParams{
		ClientID: &clientId,
	})
	if err != nil {
		return "", err
	}
	if len(clients) != 1 {
		return "", fmt.Errorf("found %d clients for %s", len(clients), clientId)
	}

	client := clients[0]

	creds, err := goclaokClient.GetClientSecret(ctx, token.AccessToken, config.Realm, *client.ID)

	if err != nil {
		return "", err
	}

	return *creds.Value, nil
}
