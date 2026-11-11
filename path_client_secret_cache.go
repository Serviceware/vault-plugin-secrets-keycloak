package keycloak

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageCacheKey    = "cache/realms/%s/clients/%s"
	storageCachePrefix = "cache/"

	// optionalSecretMaxStaleness is how long a cached client secret may be served while Keycloak is unavailable.
	optionalSecretMaxStaleness = 24 * time.Hour
	// cachePersistRefreshInterval is how old the persisted RetrievedAt may get before an unchanged entry is written again.
	cachePersistRefreshInterval = time.Hour
)

// cachedClientSecret is the last value successfully fetched from Keycloak for a client.
type cachedClientSecret struct {
	ServerUrl    string `json:"server_url"`
	ClientSecret string `json:"client_secret"`
	// Issuer is empty if it could not be retrieved from Keycloak.
	Issuer      string    `json:"issuer"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

func (c cachedClientSecret) sameValues(other cachedClientSecret) bool {
	return c.ServerUrl == other.ServerUrl && c.ClientSecret == other.ClientSecret && c.Issuer == other.Issuer
}

type clientSecretCacheKey struct {
	realm    string
	clientId string
}

func (k clientSecretCacheKey) storageKey() string {
	return fmt.Sprintf(storageCacheKey, k.realm, k.clientId)
}

// clientSecretCacheEntry is the in-memory state for a cached client secret.
type clientSecretCacheEntry struct {
	current cachedClientSecret
	// persisted is what is known to be in storage, nil if nothing is.
	persisted *cachedClientSecret
}

func readCacheForKey(ctx context.Context, storage logical.Storage, storageKey string) (*cachedClientSecret, error) {
	entry, err := storage.Get(ctx, storageKey)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cached cachedClientSecret
	if err := entry.DecodeJSON(&cached); err != nil {
		return nil, err
	}
	return &cached, nil
}

func writeCacheForKey(ctx context.Context, storage logical.Storage, cached cachedClientSecret, storageKey string) error {
	entry, err := logical.StorageEntryJSON(storageKey, cached)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// lookupCachedSecret returns the cached client secret for realm and clientId, or nil if there is none for serverUrl.
// Memory is checked first; on a miss the entry is read from storage.
func (b *backend) lookupCachedSecret(ctx context.Context, storage logical.Storage, realm string, clientId string, serverUrl string) *cachedClientSecret {
	key := clientSecretCacheKey{realm: realm, clientId: clientId}

	b.cacheMutex.RLock()
	entry, ok := b.cache[key]
	var cached cachedClientSecret
	if ok {
		cached = entry.current
	}
	b.cacheMutex.RUnlock()

	if !ok {
		stored, err := readCacheForKey(ctx, storage, key.storageKey())
		if err != nil {
			b.logger.Warn("failed to read cached client secret", "realm", realm, "client_id", clientId, "error", err)
			return nil
		}
		if stored == nil {
			return nil
		}

		b.cacheMutex.Lock()
		if entry, ok := b.cache[key]; ok {
			// populated concurrently, prefer the newer in-memory value
			cached = entry.current
		} else {
			persisted := *stored
			b.cache[key] = &clientSecretCacheEntry{current: *stored, persisted: &persisted}
			cached = *stored
		}
		b.cacheMutex.Unlock()
	}

	if cached.ServerUrl != serverUrl {
		return nil
	}
	return &cached
}

// storeCachedSecret records a successfully fetched client secret. Memory is always updated; storage is written only if
// a value changed or the persisted entry is older than cachePersistRefreshInterval. Storage errors are logged, not returned.
func (b *backend) storeCachedSecret(ctx context.Context, storage logical.Storage, key clientSecretCacheKey, cached cachedClientSecret) {
	b.cacheMutex.Lock()
	defer b.cacheMutex.Unlock()

	entry, ok := b.cache[key]
	if !ok {
		entry = &clientSecretCacheEntry{}
		b.cache[key] = entry
	}
	entry.current = cached

	if entry.persisted != nil && entry.persisted.sameValues(cached) && cached.RetrievedAt.Sub(entry.persisted.RetrievedAt) <= cachePersistRefreshInterval {
		return
	}

	if err := writeCacheForKey(ctx, storage, cached, key.storageKey()); err != nil {
		if errors.Is(err, logical.ErrReadOnly) {
			b.logger.Debug("storage is read-only, keeping cached client secret in memory only", "realm", key.realm, "client_id", key.clientId)
		} else {
			b.logger.Warn("failed to persist cached client secret", "realm", key.realm, "client_id", key.clientId, "error", err)
		}
		return
	}
	persisted := cached
	entry.persisted = &persisted
}
