package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var assets embed.FS

type Certificate struct {
	Mount       string    `json:"mount"`
	Serial      string    `json:"serial"`
	Subject     string    `json:"subject"`
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	ValidFrom   time.Time `json:"validFrom"`
	Expires     time.Time `json:"expires"`
	Fingerprint string    `json:"fingerprint"`
	Revoked     bool      `json:"revoked"`
}
type Snapshot struct {
	Certificates []Certificate `json:"certificates"`
	LastSuccess  *time.Time    `json:"lastSuccess"`
	Error        string        `json:"error"`
	Refreshing   bool          `json:"refreshing"`
}
type Watcher struct {
	client             *http.Client
	address, tokenFile string
	mu                 sync.RWMutex
	snapshot           Snapshot
	busy               bool
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func (w *Watcher) request(ctx context.Context, method, path string, out any, emptyOK bool) error {
	token, err := os.ReadFile(w.tokenFile)
	if err != nil {
		return errors.New("cannot read Agent token sink")
	}
	req, err := http.NewRequestWithContext(ctx, method, w.address+"/v1/"+path, nil)
	if err != nil {
		return errors.New("invalid Vault request")
	}
	req.Header.Set("X-Vault-Token", strings.TrimSpace(string(token)))
	resp, err := w.client.Do(req)
	if err != nil {
		return errors.New("Vault connection or TLS verification failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 && emptyOK {
		return nil
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Vault %s %s returned HTTP %d", method, path, resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return errors.New("invalid Vault response")
	}
	return nil
}
func (w *Watcher) list(ctx context.Context, path string) ([]string, error) {
	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := w.request(ctx, "LIST", path, &result, true)
	return result.Data.Keys, err
}
func normalize(s string) string { return strings.ReplaceAll(strings.ToLower(s), "-", ":") }
func (w *Watcher) inventory(ctx context.Context) ([]Certificate, error) {
	var mounts struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := w.request(ctx, "GET", "sys/mounts", &mounts, false); err != nil {
		return nil, err
	}
	certs := []Certificate{}
	for mount, info := range mounts.Data {
		if info.Type != "pki" {
			continue
		}
		mount = strings.TrimSuffix(mount, "/")
		serials, err := w.list(ctx, mount+"/certs")
		if err != nil {
			return nil, err
		}
		revoked, err := w.list(ctx, mount+"/certs/revoked")
		if err != nil {
			return nil, err
		}
		revokedSet := map[string]bool{}
		for _, s := range revoked {
			revokedSet[normalize(s)] = true
		}
		for _, serial := range serials {
			var result struct {
				Data struct {
					Certificate    string `json:"certificate"`
					RevocationTime int64  `json:"revocation_time"`
				} `json:"data"`
			}
			if err := w.request(ctx, "GET", mount+"/cert/"+serial, &result, false); err != nil {
				return nil, err
			}
			block, _ := pem.Decode([]byte(result.Data.Certificate))
			if block == nil {
				return nil, fmt.Errorf("invalid certificate in %s", mount)
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("cannot parse certificate in %s", mount)
			}
			names := append([]string{}, c.DNSNames...)
			names = append(names, c.EmailAddresses...)
			for _, ip := range c.IPAddresses {
				names = append(names, ip.String())
			}
			for _, uri := range c.URIs {
				names = append(names, uri.String())
			}
			hash := sha256.Sum256(c.Raw)
			certs = append(certs, Certificate{mount, serial, c.Subject.String(), names, c.Issuer.String(), c.NotBefore, c.NotAfter, hex.EncodeToString(hash[:]), revokedSet[normalize(serial)] || result.Data.RevocationTime > 0})
		}
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].Expires.Before(certs[j].Expires) })
	return certs, nil
}
func (w *Watcher) refresh(ctx context.Context) {
	w.mu.Lock()
	if w.busy {
		w.mu.Unlock()
		return
	}
	w.busy = true
	w.snapshot.Refreshing = true
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	certs, err := w.inventory(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.busy = false
	w.snapshot.Refreshing = false
	if err != nil {
		w.snapshot.Error = err.Error()
		log.Print(err)
		return
	}
	now := time.Now().UTC()
	w.snapshot = Snapshot{Certificates: certs, LastSuccess: &now}
}
func (w *Watcher) handler(ctx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/certificates", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.RLock()
		defer w.mu.RUnlock()
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(w.snapshot)
	})
	mux.HandleFunc("POST /api/refresh", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Watcher-Request") != "refresh" {
			http.Error(rw, "Missing refresh header", http.StatusForbidden)
			return
		}
		go w.refresh(ctx)
		rw.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, r *http.Request) { rw.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /", func(rw http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		if path != "/index.html" && path != "/style.css" && path != "/app.js" {
			http.NotFound(rw, r)
			return
		}
		b, err := assets.ReadFile("web" + path)
		if err != nil {
			http.NotFound(rw, r)
			return
		}
		switch path {
		case "/style.css":
			rw.Header().Set("Content-Type", "text/css")
		case "/app.js":
			rw.Header().Set("Content-Type", "text/javascript")
		default:
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		rw.Write(b)
	})
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(rw, r)
	})
}
func main() {
	ca, err := os.ReadFile(env("VAULT_CACERT", "/ca/root-ca.pem"))
	if err != nil {
		log.Fatal("cannot read Vault CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		log.Fatal("invalid Vault CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: os.Getenv("VAULT_TLS_SERVER_NAME")}}
	w := &Watcher{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, address: strings.TrimRight(env("VAULT_ADDR", "https://vault:8200"), "/"), tokenFile: env("VAULT_TOKEN_FILE", "/sink/token"), snapshot: Snapshot{Certificates: []Certificate{}}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		for {
			w.refresh(ctx)
			interval := 5 * time.Minute
			w.mu.RLock()
			if w.snapshot.LastSuccess == nil {
				interval = 5 * time.Second
			}
			w.mu.RUnlock()
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	server := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: w.handler(ctx), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	log.Print("certificate watcher listening on ", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
