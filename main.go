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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
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
	notifier           *DiscordNotifier
	alertWindows       []expiryWindow
	mu                 sync.RWMutex
	snapshot           Snapshot
	busy               bool
	alerted            map[string]struct{}
}

type DiscordNotifier struct {
	endpoint     string
	dashboardURL string
	client       *http.Client
}

func (d *DiscordNotifier) send(ctx context.Context, cert Certificate, remaining time.Duration, window expiryWindow) error {
	fields := []discordEmbedField{
		{Name: "Subject", Value: discordFieldValue(cert.Subject)},
		{Name: "Vault mount", Value: discordFieldValue(cert.Mount), Inline: true},
		{Name: "Serial", Value: discordFieldValue(cert.Serial), Inline: true},
		{Name: "Expires (UTC)", Value: cert.Expires.UTC().Format(time.RFC3339), Inline: true},
		{Name: "Time left", Value: formatTimeLeft(remaining), Inline: true},
	}
	if d.dashboardURL != "" {
		fields = append(fields, discordEmbedField{Name: "Dashboard", Value: fmt.Sprintf("[Open dashboard](%s)", d.dashboardURL)})
	}
	payload, err := json.Marshal(discordWebhookPayload{
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("%s Certificate expires within %d days", window.emoji, window.days),
			Description: "Renew or replace this certificate before it expires.",
			Color:       window.color,
			Fields:      fields,
			Footer:      discordEmbedFooter{Text: "Vault Certificate Watcher"},
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}}, AllowedMentions: discordAllowedMentions{Parse: []string{}}})
	if err != nil {
		return errors.New("cannot encode Discord notification")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return errors.New("cannot create Discord notification")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DiscordBot (https://github.com/MikeSchouw/vault-certificate-watcher, 1.0)")
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.New("Discord connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Discord returned HTTP %d", resp.StatusCode)
	}
	return nil
}

type discordWebhookPayload struct {
	Embeds          []discordEmbed         `json:"embeds"`
	AllowedMentions discordAllowedMentions `json:"allowed_mentions"`
}

type discordAllowedMentions struct {
	Parse []string `json:"parse"`
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
	Footer      discordEmbedFooter  `json:"footer"`
	Timestamp   string              `json:"timestamp"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordEmbedFooter struct {
	Text string `json:"text"`
}

func discordFieldValue(value string) string {
	value = singleLine(value)
	if value == "" {
		return "—"
	}
	runes := []rune(value)
	if len(runes) > 1024 {
		return string(runes[:1021]) + "..."
	}
	return value
}

func formatTimeLeft(remaining time.Duration) string {
	minutes := int(remaining.Round(time.Minute) / time.Minute)
	if minutes < 0 {
		minutes = 0
	}
	days := minutes / (24 * 60)
	hours := minutes / 60 % 24
	minutes %= 60
	parts := make([]string, 0, 3)
	if days > 0 {
		unit := "days"
		if days == 1 {
			unit = "day"
		}
		parts = append(parts, fmt.Sprintf("%d %s", days, unit))
	}
	if hours > 0 {
		unit := "hours"
		if hours == 1 {
			unit = "hour"
		}
		parts = append(parts, fmt.Sprintf("%d %s", hours, unit))
	}
	if minutes > 0 {
		unit := "minutes"
		if minutes == 1 {
			unit = "minute"
		}
		parts = append(parts, fmt.Sprintf("%d %s", minutes, unit))
	}
	if len(parts) == 0 {
		return "less than 1 minute"
	}
	return strings.Join(parts, ", ")
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(strings.ToValidUTF8(value, "�")), " ")
}

type expiryAlert struct {
	key    string
	cert   Certificate
	window expiryWindow
}

type expiryWindow struct {
	days     int64
	duration time.Duration
	emoji    string
	color    int
}

func (w *Watcher) pendingAlerts(certs []Certificate, now time.Time) []expiryAlert {
	if w.notifier == nil || len(w.alertWindows) == 0 {
		return nil
	}
	alerts := make([]expiryAlert, 0)
	for _, cert := range certs {
		remaining := cert.Expires.Sub(now)
		if cert.Revoked || remaining <= 0 {
			continue
		}
		for _, window := range w.alertWindows {
			if remaining > window.duration {
				continue
			}
			key := cert.Mount + ":" + normalize(cert.Serial) + ":" + cert.Fingerprint + ":" + strconv.FormatInt(window.days, 10)
			if _, sent := w.alerted[key]; sent {
				continue
			}
			alerts = append(alerts, expiryAlert{key: key, cert: cert, window: window})
		}
	}
	return alerts
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func dashboardURL() string {
	if value := strings.TrimSpace(os.Getenv("WATCHER_DASHBOARD_URL")); value != "" {
		return value
	}
	address := net.JoinHostPort(env("WATCHER_BIND_IP", "127.0.0.1"), env("WATCHER_PORT", "8201"))
	return "http://" + address + "/"
}

func parseExpiryAlertDays(key, fallback string) (int64, error) {
	days, err := strconv.ParseInt(env(key, fallback), 10, 64)
	if err != nil || days < 1 || days > 36500 {
		return 0, fmt.Errorf("%s must be between 1 and 36500", key)
	}
	return days, nil
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
	defer func() {
		w.mu.Lock()
		w.busy = false
		w.snapshot.Refreshing = false
		w.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	certs, err := w.inventory(ctx)
	if err != nil {
		w.mu.Lock()
		w.snapshot.Error = err.Error()
		w.mu.Unlock()
		log.Print(err)
		return
	}
	now := time.Now().UTC()
	w.mu.Lock()
	w.snapshot = Snapshot{Certificates: certs, LastSuccess: &now, Refreshing: true}
	alerts := w.pendingAlerts(certs, now)
	w.mu.Unlock()
	for _, alert := range alerts {
		if err := w.notifier.send(ctx, alert.cert, alert.cert.Expires.Sub(now), alert.window); err != nil {
			log.Print("Discord notification failed: ", err)
			continue
		}
		w.mu.Lock()
		if w.alerted == nil {
			w.alerted = make(map[string]struct{})
		}
		w.alerted[alert.key] = struct{}{}
		w.mu.Unlock()
	}
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
		if path != "/index.html" && path != "/style.css" && path != "/app.js" && path != "/favicon.svg" {
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
		case "/favicon.svg":
			rw.Header().Set("Content-Type", "image/svg+xml")
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
	alertDays, err := parseExpiryAlertDays("CERT_EXPIRY_ALERT_DAYS", "15")
	if err != nil {
		log.Fatal(err)
	}
	reminderDays, err := parseExpiryAlertDays("CERT_EXPIRY_REMINDER_DAYS", "5")
	if err != nil {
		log.Fatal(err)
	}
	alertWindows := []expiryWindow{{days: alertDays, duration: time.Duration(alertDays) * 24 * time.Hour, emoji: "🟠", color: 0xF59E0B}}
	if reminderDays != alertDays {
		alertWindows = append(alertWindows, expiryWindow{days: reminderDays, duration: time.Duration(reminderDays) * 24 * time.Hour, emoji: "🚨", color: 0xDC2626})
	}
	var notifier *DiscordNotifier
	if webhook := strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")); webhook != "" {
		parsed, err := url.ParseRequestURI(webhook)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			log.Fatal("DISCORD_WEBHOOK_URL must be a valid HTTPS URL")
		}
		notifier = &DiscordNotifier{
			endpoint:     webhook,
			dashboardURL: dashboardURL(),
			client: &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		}
	}
	ca, err := os.ReadFile(env("VAULT_CACERT", "/ca/root-ca.pem"))
	if err != nil {
		log.Fatal("cannot read Vault CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		log.Fatal("invalid Vault CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: os.Getenv("VAULT_TLS_SERVER_NAME")}}
	w := &Watcher{
		client:       &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }},
		address:      strings.TrimRight(env("VAULT_ADDR", "https://vault:8200"), "/"),
		tokenFile:    env("VAULT_TOKEN_FILE", "/sink/token"),
		notifier:     notifier,
		alertWindows: alertWindows,
		snapshot:     Snapshot{Certificates: []Certificate{}},
		alerted:      make(map[string]struct{}),
	}
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
