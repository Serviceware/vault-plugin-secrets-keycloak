# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A HashiCorp Vault secrets plugin (logical backend) that serves Keycloak client secrets read-only through Vault. Written in Go; the Go toolchain is managed via mise (`mise.toml`).

## Commands

- Build plugin binary: `make build` (outputs to `vault/plugins/vault-plugin-secrets-keycloak`)
- Format: `make fmt` — CI fails on unformatted code (`test -z $(gofmt -l .)`)
- All tests: `go test ./...`
- Single test: `go test -run TestBackend_ReadClientSecret .`
- Unit tests only (skip Docker-based integration tests): `go test -run 'TestBackend_(Read|Update|Delete|Config|OnlyLogin)' .` or run specific tests from `path_*_test.go`
- Local dev run: `make build && make start` (Vault dev server with plugin dir, root token `root`), then `make enable`

Integration tests in `backend_test.go` (`TestBackend_BasicAccess`, `TestBackend_MultiRealmAccess`, `TestBackend_RealmAccessViaSpecificRealm`) require Docker: they start Keycloak containers in several versions (21.x, 25.x, 26.x) via testcontainers and provision test clients by running Terraform (mrparkers/keycloak provider) in another container. They are slow; prefer the mock-based unit tests during development.

## Architecture

The root package `keycloak` implements the Vault backend; the `keycloak/` subpackage adapts the Keycloak API.

- `backend.go` — `Factory`/`newBackend` wire up a `framework.Backend` and register all paths. The backend holds a JWT cache (`map[ConnectionConfig]*keycloak.JWT` guarded by `jwtMutex`): access tokens are reused per connection config as long as they are valid for at least 5 more seconds (checked via `util/jwt`), otherwise a fresh `LoginClient` happens.
- `path_config_connection.go` — connection configs stored in Vault storage: a default config at `config/connection` and per-realm configs at `config/realms/<realm>/connection`. Writes perform a live connectivity check (login against Keycloak) unless `ignore_connectivity_check` is set.
- `path_client_secret.go` — the read routes:
  - `client-secret/<clientId>` (deprecated)
  - `clients/<clientId>/secret` (uses default config's realm)
  - `realms/<realm>/clients/<clientId>/secret`
  - `realms/<realm>/clients/<clientId>/optional-secret` — never returns an error response; on failure it returns empty `client_secret`/`issuer` plus an `error` field. Before giving up it retries transient network errors (connection reset, EOF, timeout, …; see `isTransientNetworkError`) up to 4 attempts with exponential back-off starting at 500 ms via retry-go. Permanent errors are not retried. This behavior is documented in README.md — keep both in sync.

  Realm-scoped routes read the per-realm config first and fall back to the default config when it is empty.
- `keycloak/` subpackage — `Service` interface (`interface.go`) defines the subset of Keycloak functionality used (login, get clients, get client secret, well-known OpenID config), with types aliased from gocloak. `gocloak.go` is the real implementation; `mock.go` provides a testify-based `MockService` and `MockServiceFactoryFunc`. The backend's `KeycloakServiceFactory` field is the injection point — unit tests replace it with the mock factory.
- `util/jwt` — JWT expiry check; `util/test` — JWT generation helper for tests.

Releases are built with goreleaser (`.goreleaser.yml`) via the release GitHub workflow.
