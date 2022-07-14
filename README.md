# Keycloak Secrets via Vault

The purpose of this plugin is to provide Keycloak client secrets from Vault. 
## Setup

Please read [Vault Plugin](https://www.vaultproject.io/docs/plugins) documentation for how to enable and handle plugins in Vault.

### Register plugin

Unzip the release file and copy the plugin binary into the vault plugin folder

```
unzip vault-plugin-secrets-keycloak_0.1.0_linux_amd64.zip
cp vault-plugin-secrets-keycloak_v0.1.0 /etc/vault/plugin/keycloak-client-secrets
```

Then register the plugin:

```
vault plugin register -sha256=<checksum of the plugin binary> secret keycloak-client-secrets
```

Now, the plugin can be used in Vault.

### Mount backend

Next, you have to mount a _keycloak-client-secrets_ backend. Do this either by command line

```
vault secrets enable --path=keycloak-client-secrets keycloak-client-secrets
```

or with Terraform

```
resource "vault_mount" "keycloak-client-secrets" {
  type        = "keycloak-client-secrets"
  path        = "keycloak-client-secrets"
}
```

### Create client

Create a client in Keycloak which should be used by vault to access the client secrets. You can use our 
[Terraform plugin](https://registry.terraform.io/modules/Serviceware/keycloak-client/vaultkeycloak/0.1.2) to this:

```
provider "keycloak" {
  url       = "https://auth.example.org"
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

### Configure connection
> **Warning**
> Currently this plugin supports only Keycloak below version 17 as the `/auth` part is implictly appended to the server url
Now, you can register a connection to Keycloak with

```
vault write keycloak-client-secrets/config/connection \
    server_url="https://auth.example.org" \
    realm="master" \
    client_id="vault" \
    client_secret="secr3t"
```

or by using our [vaultkeycloak](https://registry.terraform.io/providers/Serviceware/vaultkeycloak/latest) Terraform provider

```
resource "vaultkeycloak_secret_backend" "keycloak-client-secrets-config" {
  path = "keycloak-client-secrets"
  
  server_url    = "https://auth.example.org"
  realm         = "master"
  client_id     = "vault"
  client_secret = "secr3t"
}
```

The client secret is taken from the credentials tab of the client configuration in Keycloak.

### Read client secret

Assuming, you have a client _my-client_ in Keycloak you can finally read the client secret with

```
vault read keycloak-client-secrets/client-secret/my-client
```

The output looks like this:

```
Key              Value
---              -----
client_secret    some-very-secret-value
client_id        my-client
issuer_url       https://auth.example.org/auth/realms/master
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
make enable
vault write keycloak/config/connection \
    server_url="http://localhost:8080" \
    realm="master" \
    client_id="vault" \
    client_secret="sec3t"

vault read keycloak/client-secret/foo
```
