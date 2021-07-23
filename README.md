# Keycloak Secrets via Vault

## Setup

https://www.vaultproject.io/docs/plugin

### Config

```
vault write keycloak/config/connection \
    connection_uri="http://localhost:8080" \
    realm="master" \
    client_id="vault" \
    client_secret="sec3t"
```

### Usage

```
vault read keycloak/client-secret/my-client

```

## Test Setup

First run `mockery`

## Test Run

```bash
export VAULT_ADDR="http://127.0.0.1:8200
```

```bash
make build && make start
```

```
make enable && vault read keycloak-secrets/foo
```
