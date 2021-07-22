package keycloak

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_ConfigConnection(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend()
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"server_url":    "http://auth.example.com",
		"realm":         "master",
		"client_id":     "vault",
		"client_secret": "vault123",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	actualConfig, err := readConfig(context.Background(), config.StorageView)
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig := connectionConfig{
		ServerUrl:    "http://auth.example.com",
		Realm:        "master",
		ClientId:     "vault",
		ClientSecret: "vault123",
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}
