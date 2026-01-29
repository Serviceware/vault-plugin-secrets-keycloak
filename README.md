# Keycloak Secrets via Vault

The purpose of this plugin is to provide Keycloak client secrets from Vault.

## Setup

Please read the [Vault Plugin](https://www.vaultproject.io/docs/plugins) documentation for how to enable and handle plugins in Vault.

### Register plugin

Unzip the release file and copy the plugin binary into the vault plugin folder:

```
unzip vault-plugin-secrets-keycloak_0.4.0_linux_amd64.zip
cp vault-plugin-secrets-keycloak_v0.4.0 /etc/vault/plugin/keycloak-client-secrets
```

Then register the plugin:

```
vault plugin register -sha256=<checksum of the plugin binary> secret keycloak-client-secrets
```

Now, the plugin can be used in Vault.

### Mount backend

Next, you have to mount a _keycloak-client-secrets_ backend. Do this either by command line:

```
vault secrets enable --path=keycloak-client-secrets keycloak-client-secrets
```

or with Terraform:

```
resource "vault_mount" "keycloak-client-secrets" {
  type        = "keycloak-client-secrets"
  path        = "keycloak-client-secrets"
}
```

### Create client

Create a client in Keycloak which should be used by vault to access the client secrets.
The client should be a service account role that is able to read client secrets.

You can use our
[Terraform module](https://registry.terraform.io/modules/Serviceware/keycloak-client/vaultkeycloak/latest) to do this:

```
provider "keycloak" {
  url       = "https://auth.example.org/auth"
  client_id = "admin-cli"
}

module "keycloak_vault_config" {
  source          = "Serviceware/keycloak-client/vaultkeycloak"
  version         = "0.1.2"
  realm           = "master"
  vault_client_id = "vault"
}
```

The plugin takes the credentials from the Keycloak provider.

### Default Configure connection

Now, you can register a connection to Keycloak with:

```
vault write keycloak-client-secrets/config/connection \
    server_url="https://auth.example.org/auth" \
    realm="master" \
    client_id="vault" \
    client_secret="secr3t"
```

or by using our [vaultkeycloak](https://registry.terraform.io/providers/Serviceware/vaultkeycloak/latest) Terraform provider:

```
resource "vaultkeycloak_secret_backend" "keycloak-client-secrets-config" {
  path = "keycloak-client-secrets"

  server_url    = "https://auth.example.org/auth"
  realm         = "master"
  client_id     = "vault"
  client_secret = "secr3t"
}
```

The client secret is taken from the credentials tab of the client configuration in Keycloak.

### Configure connection for specific realm

```
vault write keycloak-client-secrets/config/realms/realm123/connection \
    server_url="https://auth.example.org/auth" \
    client_id="vault" \
    client_secret="secr3t"
```

### Read client secret of "default" realm

Assuming, you have a client _my-client_ in Keycloak you can finally read the client secret with:

```
vault read keycloak-client-secrets/clients/my-client/secret
```

The output looks like this:

```
Key              Value
---              -----
client_secret    some-very-secret-value
client_id        my-client
issuer           https://auth.example.org/auth/realms/master
```

### Read client secret of specific realm

```
vault read keycloak-client-secrets/realms/my-realm/clients/my-client/secret
```

The output looks like this:

```
Key              Value
---              -----
client_secret    some-very-secret-value
client_id        my-client
issuer           https://auth.example.org/auth/realms/master
```

### Read client secret with optional-secret (non-failing)

The `optional-secret` endpoint works like the regular `/secret` endpoint but does not return an error if Keycloak is unavailable or the client secret cannot be retrieved. Instead, it returns empty values along with an error message in the response. This is useful for scenarios where you want to gracefully handle Keycloak unavailability.

```
vault read keycloak-client-secrets/realms/my-realm/clients/my-client/optional-secret
```

On success, the output looks like this:

```
Key              Value
---              -----
client_id        my-client
client_secret    some-very-secret-value
error            <nil>
issuer           https://auth.example.org/auth/realms/master
```

If Keycloak is unavailable or the secret cannot be retrieved, the request still succeeds but returns empty values with an error message:

```
Key              Value
---              -----
client_id        my-client
client_secret
error            could not retrieve client secret for client my-client in realm my-realm: ...
issuer
```

## Test Run

```bash
export VAULT_ADDR="http://127.0.0.1:8200
```

```bash
make build && make start
```

```
make enable
vault write keycloak/config/connection \
    server_url="http://localhost:8080/auth" \
    realm="master" \
    client_id="vault" \
    client_secret="sec3t"

vault read keycloak/clients/foo/secret
```
