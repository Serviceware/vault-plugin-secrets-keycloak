// Package keycloaksearvice adapts keycloak functionality.
// Its core is the [KeycloakService] and its implementations.
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
type WellKnownOpenidConfiguration struct {
	Issuer string `json:"issuer"`
}

// KeycloakService describes the relevant subset of keycloak functionality for providing secrets to vault.
type KeycloakService interface {
	// Defining the same methods as gocloak.GoCloak.
	// I know it looks not clean when I leak gocloak types, but I don't want to reimplement all the structs
	LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*gocloak.JWT, error)
	GetClients(ctx context.Context, token string, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*gocloak.CredentialRepresentation, error)
	GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error)
}

// KeycloakServiceFactory abstracts the creation of a new [KeycloakService] instance.
type KeycloakServiceFactory interface {
	NewClient(ctx context.Context, connConfig ConnectionConfig) (KeycloakService, error)
}
