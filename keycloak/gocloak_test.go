package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/require"
)

func TestGocloakGetWellKnownOpenidConfigurationReturnsHTTPStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := NewGocloakClient(server.URL).GetWellKnownOpenidConfiguration(t.Context(), "somerealm")

	var statusErr *HTTPStatusError
	require.ErrorAs(t, err, &statusErr)
	require.Equal(t, http.StatusServiceUnavailable, statusErr.StatusCode)
	require.Equal(t, server.URL+"/realms/somerealm/.well-known/openid-configuration", statusErr.URL)
}

func TestGocloakGetWellKnownOpenidConfigurationDecodesIssuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/realms/somerealm/.well-known/openid-configuration", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"THIS_IS_THE_ISSUER"}`))
	}))
	defer server.Close()

	config, err := NewGocloakClient(server.URL).GetWellKnownOpenidConfiguration(t.Context(), "somerealm")
	require.NoError(t, err)
	require.Equal(t, "THIS_IS_THE_ISSUER", config.Issuer)
}

func TestGocloakGetWellKnownOpenidConfigurationHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_, err := NewGocloakClient(server.URL).GetWellKnownOpenidConfiguration(ctx, "somerealm")
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestGocloakTranslateError(t *testing.T) {
	var transportErr *TransportError
	err := translateGocloakError(&gocloak.APIError{Code: 0, Message: "could not get token: connection refused"})
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, "could not get token: connection refused", err.Error())

	var statusErr *HTTPStatusError
	err = translateGocloakError(&gocloak.APIError{Code: 503, Message: "503 Service Unavailable"})
	require.ErrorAs(t, err, &statusErr)
	require.Equal(t, 503, statusErr.StatusCode)
	require.Equal(t, "503 Service Unavailable", err.Error())

	plain := errors.New("plain")
	require.Same(t, plain, translateGocloakError(plain))
}
