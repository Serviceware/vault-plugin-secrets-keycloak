# Changelog

## v0.7.1
- Fixes a bug where the different access token for different keycloak configurations were not correctly cached.

## v0.7.0
- Retains access token until `exp - 5s` to reduce the amount of client id logins of the vault backend
