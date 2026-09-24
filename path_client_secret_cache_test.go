package keycloak

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Serviceware/vault-plugin-secrets-keycloak/keycloak"
	testutil "github.com/Serviceware/vault-plugin-secrets-keycloak/util/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	cacheTestRealm     = "somerealm"
	cacheTestClientId  = "myclient"
	cacheTestServerUrl = "http://example.com/auth"
	cacheTestIssuer    = "THIS_IS_THE_ISSUER"
	cacheTestSecret    = "mysecret123"
	cacheTestPath      = "realms/" + cacheTestRealm + "/clients/" + cacheTestClientId + "/optional-secret"
	cacheTestStoreKey  = "cache/realms/" + cacheTestRealm + "/clients/" + cacheTestClientId
	cacheTestLoginErr  = "could not retrieve client secret for client myclient in realm somerealm: failed to login: connection refused"
	cacheTestIssuerErr = "could not retrieve issuer for client myclient in realm somerealm: "
)

var errCacheTestTransient = &keycloak.TransportError{Message: "connection refused"}

// requireRetrievedAt asserts that data contains an RFC3339 retrieved_at, removes it and returns it.
func requireRetrievedAt(t *testing.T, data map[string]interface{}) time.Time {
	t.Helper()
	raw, ok := data["retrieved_at"].(string)
	require.True(t, ok, "retrieved_at missing: %#v", data)
	retrievedAt, err := time.Parse(time.RFC3339, raw)
	require.NoError(t, err)
	delete(data, "retrieved_at")
	return retrievedAt
}

// countingStorage counts writes below cache/ and optionally rejects them as read-only.
type countingStorage struct {
	logical.Storage

	mu        sync.Mutex
	cachePuts int
	readOnly  bool
}

func (s *countingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, storageCachePrefix) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.readOnly {
			return logical.ErrReadOnly
		}
		s.cachePuts++
	}
	return s.Storage.Put(ctx, entry)
}

func (s *countingStorage) puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cachePuts
}

// keycloakUpMock serves secret and issuer. The access token expires immediately, so every read logs in.
func keycloakUpMock(secret string, issuer string) *keycloak.MockService {
	jwt := testutil.JWT(0)
	id := "123"
	clientId := cacheTestClientId
	m := &keycloak.MockService{}
	m.On("LoginClient", mock.Anything, "vaultforrealm", "vaultforrealm_secret123", cacheTestRealm).Return(&keycloak.JWT{AccessToken: jwt}, nil)
	m.On("GetClients", mock.Anything, jwt, cacheTestRealm, keycloak.GetClientsParams{ClientID: &clientId}).Return([]*keycloak.Client{{ID: &id}}, nil)
	m.On("GetClientSecret", mock.Anything, jwt, cacheTestRealm, id).Return(&keycloak.CredentialRepresentation{Value: &secret}, nil)
	m.On("GetWellKnownOpenidConfiguration", mock.Anything, cacheTestRealm).Return(&keycloak.WellKnownOpenidConfiguration{Issuer: issuer}, nil)
	return m
}

// keycloakDownMock fails every call with err.
func keycloakDownMock(err error) *keycloak.MockService {
	m := &keycloak.MockService{}
	m.On("LoginClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, err)
	m.On("GetClients", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, err)
	m.On("GetClientSecret", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, err)
	m.On("GetWellKnownOpenidConfiguration", mock.Anything, mock.Anything).Return(nil, err)
	return m
}

// keycloakIssuerDownMock serves secret but fails the issuer lookup with err.
func keycloakIssuerDownMock(secret string, err error) *keycloak.MockService {
	m := keycloakUpMock(secret, "")
	m.ExpectedCalls = m.ExpectedCalls[:3]
	m.On("GetWellKnownOpenidConfiguration", mock.Anything, cacheTestRealm).Return(nil, err)
	return m
}

func newCacheTestBackend(t *testing.T, storage logical.Storage) *backend {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = storage
	b, err := newBackend(config)
	require.NoError(t, err)
	require.NoError(t, b.Setup(t.Context(), config))
	return b
}

func newCacheTestStorage(t *testing.T) *countingStorage {
	t.Helper()
	storage := &countingStorage{Storage: &logical.InmemStorage{}}
	writeCacheTestRealmConfig(t, storage, cacheTestServerUrl)
	return storage
}

func writeCacheTestRealmConfig(t *testing.T, storage logical.Storage, serverUrl string) {
	t.Helper()
	require.NoError(t, writeConfigForKey(t.Context(), storage, ConnectionConfig{
		ClientId:     "vaultforrealm",
		ClientSecret: "vaultforrealm_secret123",
		Realm:        cacheTestRealm,
		ServerUrl:    serverUrl,
	}, realmSpecificStorageKey(cacheTestRealm)))
}

func readOptionalSecret(t *testing.T, b *backend, storage logical.Storage, service keycloak.Service) *logical.Response {
	t.Helper()
	b.KeycloakServiceFactory = keycloak.MockServiceFactoryFunc(service.(*keycloak.MockService))
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      cacheTestPath,
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	return resp
}

func emptyOptionalSecretResponse(message string) map[string]interface{} {
	return map[string]interface{}{
		"client_secret": "",
		"client_id":     cacheTestClientId,
		"issuer":        "",
		"error":         message,
	}
}

func TestBackend_ReadOptionalClientSecretCacheMissPersists(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		resp := readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		retrievedAt := requireRetrievedAt(t, resp.Data)
		require.Equal(t, time.Now().Truncate(time.Second), retrievedAt.Local())
		require.Equal(t, map[string]interface{}{
			"client_secret": cacheTestSecret,
			"client_id":     cacheTestClientId,
			"issuer":        cacheTestIssuer,
			"error":         nil,
			"stale":         false,
		}, resp.Data)
		require.Empty(t, resp.Warnings)

		cached, err := readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.NotNil(t, cached)
		require.Equal(t, cacheTestServerUrl, cached.ServerUrl)
		require.Equal(t, cacheTestSecret, cached.ClientSecret)
		require.Equal(t, cacheTestIssuer, cached.Issuer)
		require.True(t, cached.RetrievedAt.Equal(time.Now()))
		require.Equal(t, 1, storage.puts())
	})
}

func TestBackend_ReadOptionalClientSecretCacheWritesOnlyOnChangeOrRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		require.Equal(t, 1, storage.puts())

		time.Sleep(time.Minute)
		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		require.Equal(t, 1, storage.puts(), "unchanged values must not be written again")

		time.Sleep(61 * time.Minute)
		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		require.Equal(t, 2, storage.puts(), "persisted timestamp older than 1h must be refreshed")

		readOptionalSecret(t, b, storage, keycloakUpMock("rotated", cacheTestIssuer))
		require.Equal(t, 3, storage.puts(), "changed secret must be written")
	})
}

func TestBackend_ReadOptionalClientSecretCacheServesCachedIssuer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		firstRetrievedAt := time.Now().UTC().Format(time.RFC3339)
		time.Sleep(time.Minute)

		// transient issuer error: cached issuer, live secret
		resp := readOptionalSecret(t, b, storage, keycloakIssuerDownMock("rotated", errCacheTestTransient))
		requireRetrievedAt(t, resp.Data)
		require.Equal(t, map[string]interface{}{
			"client_secret": "rotated",
			"client_id":     cacheTestClientId,
			"issuer":        cacheTestIssuer,
			"error":         nil,
			"stale":         true,
		}, resp.Data)
		require.Equal(t, []string{"serving cached issuer retrieved at " + firstRetrievedAt + ": " + cacheTestIssuerErr + "connection refused"}, resp.Warnings)

		cached, err := readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.Equal(t, "rotated", cached.ClientSecret)
		require.Equal(t, cacheTestIssuer, cached.Issuer)

		// permanent issuer error: issuer derived from server_url, cached issuer is kept
		resp = readOptionalSecret(t, b, storage, keycloakIssuerDownMock("rotated", &keycloak.HTTPStatusError{StatusCode: 404, URL: "x"}))
		requireRetrievedAt(t, resp.Data)
		require.Equal(t, cacheTestServerUrl+"/realms/"+cacheTestRealm, resp.Data["issuer"])
		require.Equal(t, false, resp.Data["stale"])
		require.Len(t, resp.Warnings, 1)
		require.True(t, strings.HasPrefix(resp.Warnings[0], "using issuer derived from server_url: "))

		cached, err = readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.Equal(t, cacheTestIssuer, cached.Issuer)
	})
}

func TestBackend_ReadOptionalClientSecretCacheDoesNotPersistConstructedIssuer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		resp := readOptionalSecret(t, b, storage, keycloakIssuerDownMock(cacheTestSecret, errCacheTestTransient))
		require.Equal(t, cacheTestServerUrl+"/realms/"+cacheTestRealm, resp.Data["issuer"])
		require.Equal(t, false, resp.Data["stale"])

		cached, err := readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.Equal(t, cacheTestSecret, cached.ClientSecret)
		require.Equal(t, "", cached.Issuer)

		// a later success replaces the empty issuer
		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		cached, err = readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.Equal(t, cacheTestIssuer, cached.Issuer)
	})
}

func TestBackend_ReadOptionalClientSecretCacheServesStaleOnTransientFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		retrievedAt := time.Now().UTC().Format(time.RFC3339)

		time.Sleep(23 * time.Hour)
		resp := readOptionalSecret(t, b, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, map[string]interface{}{
			"client_secret": cacheTestSecret,
			"client_id":     cacheTestClientId,
			"issuer":        cacheTestIssuer,
			"error":         nil,
			"stale":         true,
			"retrieved_at":  retrievedAt,
		}, resp.Data)
		require.Equal(t, []string{"serving cached client secret retrieved at " + retrievedAt + " because Keycloak is unavailable: " + cacheTestLoginErr}, resp.Warnings)
	})
}

func TestBackend_ReadOptionalClientSecretCacheExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))

		time.Sleep(25 * time.Hour)
		resp := readOptionalSecret(t, b, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, emptyOptionalSecretResponse(cacheTestLoginErr), resp.Data)
		require.Equal(t, []string{cacheTestLoginErr}, resp.Warnings)
	})
}

func TestBackend_ReadOptionalClientSecretCacheEmpty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		resp := readOptionalSecret(t, b, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, emptyOptionalSecretResponse(cacheTestLoginErr), resp.Data)
		require.Equal(t, []string{cacheTestLoginErr}, resp.Warnings)
	})
}

func TestBackend_ReadOptionalClientSecretCacheNotServedOnPermanentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))

		noClients := keycloakUpMock(cacheTestSecret, cacheTestIssuer)
		noClients.ExpectedCalls[1].ReturnArguments = mock.Arguments{[]*keycloak.Client{}, nil}
		resp := readOptionalSecret(t, b, storage, noClients)
		message := "could not retrieve client secret for client myclient in realm somerealm: found 0 clients for myclient"
		require.Equal(t, emptyOptionalSecretResponse(message), resp.Data)

		resp = readOptionalSecret(t, b, storage, keycloakDownMock(&keycloak.HTTPStatusError{StatusCode: 401, Message: "401 Unauthorized"}))
		message = "could not retrieve client secret for client myclient in realm somerealm: failed to login: 401 Unauthorized"
		require.Equal(t, emptyOptionalSecretResponse(message), resp.Data)
	})
}

func TestBackend_ReadOptionalClientSecretCacheIgnoredAfterServerUrlChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b := newCacheTestBackend(t, storage)

		readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))

		writeCacheTestRealmConfig(t, storage, "http://other.example.com/auth")
		resp := readOptionalSecret(t, b, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, emptyOptionalSecretResponse(cacheTestLoginErr), resp.Data)
	})
}

func TestBackend_ReadOptionalClientSecretCacheReadOnlyStorage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		storage.readOnly = true
		b := newCacheTestBackend(t, storage)

		resp := readOptionalSecret(t, b, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))
		require.Equal(t, cacheTestSecret, resp.Data["client_secret"])
		require.Equal(t, false, resp.Data["stale"])

		cached, err := readCacheForKey(t.Context(), storage, cacheTestStoreKey)
		require.NoError(t, err)
		require.Nil(t, cached)

		resp = readOptionalSecret(t, b, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, cacheTestSecret, resp.Data["client_secret"])
		require.Equal(t, true, resp.Data["stale"])
	})
}

func TestBackend_ReadOptionalClientSecretCacheColdStartReadThrough(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newCacheTestStorage(t)
		b1 := newCacheTestBackend(t, storage)
		readOptionalSecret(t, b1, storage, keycloakUpMock(cacheTestSecret, cacheTestIssuer))

		b2 := newCacheTestBackend(t, storage)
		resp := readOptionalSecret(t, b2, storage, keycloakDownMock(errCacheTestTransient))
		require.Equal(t, cacheTestSecret, resp.Data["client_secret"])
		require.Equal(t, cacheTestIssuer, resp.Data["issuer"])
		require.Equal(t, true, resp.Data["stale"])
	})
}

func TestIsTransientNetworkErrorHTTPStatus(t *testing.T) {
	require.True(t, isTransientNetworkError(&keycloak.HTTPStatusError{StatusCode: 502}))
	require.True(t, isTransientNetworkError(&keycloak.HTTPStatusError{StatusCode: 503}))
	require.True(t, isTransientNetworkError(&keycloak.HTTPStatusError{StatusCode: 504}))
	require.False(t, isTransientNetworkError(&keycloak.HTTPStatusError{StatusCode: 404}))
	require.False(t, isTransientNetworkError(&keycloak.HTTPStatusError{StatusCode: 401}))
	require.True(t, isTransientNetworkError(errCacheTestTransient))
	require.True(t, isTransientNetworkError(errors.Join(errors.New("failed to login"), &keycloak.HTTPStatusError{StatusCode: 503})))
}
