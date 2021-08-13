module github.com/Serviceware/vault-plugin-secrets-keycloak

go 1.16

require (
	github.com/Nerzal/gocloak/v8 v8.5.0
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/docker/go-connections v0.4.0
	github.com/go-resty/resty/v2 v2.3.0
	github.com/hashicorp/go-hclog v0.16.1
	github.com/hashicorp/vault v1.7.3
	github.com/hashicorp/vault/api v1.0.5-0.20210210214158-405eced08457
	github.com/hashicorp/vault/sdk v0.2.1-0.20210614231108-a35199734e5f
	github.com/mitchellh/mapstructure v1.3.3
	github.com/stretchr/testify v1.7.0
	github.com/testcontainers/testcontainers-go v0.11.1
	gopkg.in/ini.v1 v1.51.0 // indirect
)
