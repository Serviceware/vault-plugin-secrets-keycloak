# Changelog

## Unreleased
- `optional-secret` serves the last successfully retrieved client secret and issuer (up to 24h old, `stale: true`) when Keycloak is unavailable, instead of an empty secret. Responses gain `stale` and `retrieved_at` fields.
- `optional-secret` falls back to the cached issuer, or `<server_url>/realms/<realm>`, when only the issuer lookup fails, instead of returning an empty secret.
- Network errors and HTTP 502/503/504 from Keycloak's token and admin API are now recognized as transient, so they are retried on `optional-secret`.
- The OpenID configuration request honours the request context, has a 10s timeout, closes the response body and reports non-2xx responses as errors.

## v0.8.0
- Adds `optional-secret` endpoint to gracefully handle Keycloak unavailability
- Fixes vulnerable dependencies
- Avoids memory allocation for JWT decomposition

## v0.7.1
- Fixes a bug where the different access token for different keycloak configurations were not correctly cached.

## v0.7.0
- Retains access token until `exp - 5s` to reduce the amount of client id logins of the vault backend
