package keycloak

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v8"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathClientSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "client-secret/" + framework.GenericNameRegex("clientId"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
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
		return logical.ErrorResponse("missing clientId"), nil
	}

	config, err := readConfig(ctx, req.Storage)

	if err != nil {
		return nil, err
	}
	goclaokClient, err := b.Client(ctx, req.Storage)

	if err != nil {
		return nil, err
	}

	token, err := goclaokClient.LoginClient(ctx, config.ClientId, config.ClientSecret, config.Realm)
	if err != nil {
		return nil, err
	}

	clients, err := goclaokClient.GetClients(ctx, token.AccessToken, config.Realm, gocloak.GetClientsParams{
		ClientID: &clientId,
	})
	if err != nil {
		return nil, err
	}
	if len(clients) != 1 {
		return nil, fmt.Errorf("found %d clients for %s", len(clients), clientId)
	}

	client := clients[0]

	creds, err := goclaokClient.GetClientSecret(ctx, token.AccessToken, config.Realm, *client.ID)

	if err != nil {
		return nil, err
	}

	// Generate the response
	response := &logical.Response{
		Data: map[string]interface{}{
			"client_secret": creds.Value,
		},
	}

	return response, nil
}
