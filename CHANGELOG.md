# Changelog

## v0.8.0
- Adds `optional-secret` endpoint to gracefully handle Keycloak unavailability
- Fixes vulnerable dependencies
- Avoids memory allocation for JWT decomposition

## v0.7.1
- Fixes a bug where the different access token for different keycloak configurations were not correctly cached.

## v0.7.0
- Retains access token until `exp - 5s` to reduce the amount of client id logins of the vault backend
