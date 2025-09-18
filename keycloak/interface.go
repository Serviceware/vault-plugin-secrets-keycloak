// Package keycloak adapts keycloak functionality.
// Its core is the [Service] and its implementations, especially [GocloakService].
package keycloak

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

// Types, that the [Service] returns.
// Defined in terms of gocloak types as a compromise between decoupling and practicality.
type (
	JWT                      gocloak.JWT
	Client                   gocloak.Client
	GetClientsParams         gocloak.GetClientsParams
	CredentialRepresentation gocloak.CredentialRepresentation
)

// Service describes the relevant subset of keycloak functionality for providing secrets to vault.
type Service interface {
	// Defining the methods in the style of [gocloak.GoCloak].
	LoginClient(ctx context.Context, clientID string, clientSecret string, realm string) (*JWT, error)
	GetClients(ctx context.Context, token string, realm string, params GetClientsParams) ([]*Client, error)
	GetClientSecret(ctx context.Context, token string, realm string, clientID string) (*CredentialRepresentation, error)
	GetWellKnownOpenidConfiguration(ctx context.Context, realm string) (*WellKnownOpenidConfiguration, error)
}

// ServiceFactoryFunc is a kind of function that creates new [Service] instances.
type ServiceFactoryFunc func(ctx context.Context, connConfig ConnectionConfig) (Service, error)
