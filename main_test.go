package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshRetainsSnapshotOnFailure(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"test.example"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Error("missing token")
		}
		if fail {
			w.WriteHeader(403)
			return
		}
		var data any
		switch r.URL.Path {
		case "/v1/sys/mounts":
			data = map[string]any{"nested/pki/": map[string]string{"type": "pki"}, "kv/": map[string]string{"type": "kv"}}
		case "/v1/nested/pki/certs":
			if r.Method != "LIST" {
				t.Error("expected LIST")
			}
			data = map[string]any{"keys": []string{"01"}}
		case "/v1/nested/pki/certs/revoked":
			data = map[string]any{"keys": []string{"01"}}
		case "/v1/nested/pki/cert/01":
			data = map[string]any{"certificate": cert}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("test-token\n"), 0600)
	watcher := &Watcher{client: server.Client(), address: server.URL, tokenFile: token}
	watcher.refresh(context.Background())
	if watcher.snapshot.Error != "" || len(watcher.snapshot.Certificates) != 1 {
		t.Fatalf("bad result: %+v", watcher.snapshot)
	}
	c := watcher.snapshot.Certificates[0]
	if !c.Revoked || len(c.Fingerprint) != 64 || c.Names[0] != "test.example" {
		t.Fatalf("bad certificate: %+v", c)
	}
	success := watcher.snapshot.LastSuccess
	fail = true
	watcher.refresh(context.Background())
	if watcher.snapshot.Error == "" || watcher.snapshot.LastSuccess != success || len(watcher.snapshot.Certificates) != 1 {
		t.Fatal("failed refresh discarded snapshot")
	}
}
func TestRefreshHeader(t *testing.T) {
	w := &Watcher{}
	request := httptest.NewRequest("POST", "/api/refresh", nil)
	response := httptest.NewRecorder()
	w.handler(context.Background()).ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal(response.Code)
	}
}
