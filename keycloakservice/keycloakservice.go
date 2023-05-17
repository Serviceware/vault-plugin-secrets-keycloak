package keycloakservice

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

type ConnectionConfig struct {
	ServerUrl    string
	Realm        string
	ClientId     string
	ClientSecret string
}

type KeycloakService interface {
	// defin the same methods as gocloak.GoCloak (only LoginClient, GetClients, GetClientSecret are used)
	LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*gocloak.JWT, error)
	GetClients(ctx context.Context, token string, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*gocloak.CredentialRepresentation, error)
}
type KeycloakServiceFactory interface {
	NewClient(ctx context.Context, connConfig ConnectionConfig) (KeycloakService, error)
}
