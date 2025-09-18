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

// Types, that the [KeycloakService] returns.
// Defined in terms of gocloak types as a compromise between decoupling and practicality.
type (
	JWT                      gocloak.JWT
	Client                   gocloak.Client
	GetClientsParams         gocloak.GetClientsParams
	CredentialRepresentation gocloak.CredentialRepresentation
)

// KeycloakService describes the relevant subset of keycloak functionality for providing secrets to vault.
type KeycloakService interface {
	// Defining the methods in the style of [gocloak.GoCloak].
	LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error)
	GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error)
	GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error)
	GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error)
}

// KeycloakServiceFactory abstracts the creation of a new [KeycloakService] instance.
type KeycloakServiceFactory interface {
	NewClient(ctx context.Context, connConfig ConnectionConfig) (KeycloakService, error)
}
