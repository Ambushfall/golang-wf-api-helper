package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
)

var (
	authzPattern    = regexp.MustCompile(`\?accountId=([0-9a-fA-F]{24})&nonce=(\d+)`)
	errUnauthorized = errors.New("session unauthorized or expired")
)

type ServiceConfig struct {
	Interval       time.Duration
	MaxFailureTime time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	OutputDir      string
}

type InventoryService struct {
	cfg    ServiceConfig
	client *http.Client
	mu     sync.Mutex
	authz  string
}

func NewInventoryService(cfg ServiceConfig) *InventoryService {
	return &InventoryService{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *InventoryService) refreshToken() error {
	pid, err := findWarframePID()
	if err != nil {
		return fmt.Errorf("process lookup failed: %w", err)
	}

	candidates := make(map[string]int)
	var found string

	err = scanProcessMemory(pid, func(chunk []byte) bool {
		for _, match := range authzPattern.FindAllSubmatch(chunk, -1) {
			candidate := fmt.Sprintf("?accountId=%s&nonce=%s", match[1], match[2])
			candidates[candidate]++
			if candidates[candidate] == 3 {
				found = candidate
				return true
			}
		}
		return false
	})

	if err != nil {
		return fmt.Errorf("memory scan failed: %w", err)
	}

	if found == "" {
		return fmt.Errorf("auth token not found in process memory")
	}

	s.mu.Lock()
	s.authz = found
	s.mu.Unlock()
	log.Println("[auth] Acquired session token from Warframe process")
	return nil
}

func (s *InventoryService) getCachedToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authz
}

func (s *InventoryService) clearToken() {
	s.mu.Lock()
	s.authz = ""
	s.mu.Unlock()
}

func (s *InventoryService) fetchAndSave(ctx context.Context, authz string) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://mobile.warframe.com/api/inventory.php"+authz,
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
		return errUnauthorized
	}

	// Јебеш га сад, ко зна који му је курац..
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading response body: %w", err)
	}

	if bytes.Contains(rawBody[:min(len(rawBody), 256)], []byte("Invalid session")) {
		return errUnauthorized
	}

	var decoded map[string]any
	if err := json.Unmarshal(rawBody, &decoded); err != nil {
		return fmt.Errorf("invalid JSON response: %w", err)
	}

	var pretty bytes.Buffer
	enc := json.NewEncoder(&pretty)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decoded); err != nil {
		return fmt.Errorf("json encode failed: %w", err)
	}

	outPath := filepath.Join(s.cfg.OutputDir, "inventory.json")
	if err := os.WriteFile(outPath, pretty.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed writing inventory.json: %w", err)
	}

	return nil
}

// токен .. грешка .. освежи
func (s *InventoryService) syncAttempt(ctx context.Context) error {
	token := s.getCachedToken()
	if token == "" {
		if err := s.refreshToken(); err != nil {
			return err
		}
		token = s.getCachedToken()
	}

	err := s.fetchAndSave(ctx, token)
	if errors.Is(err, errUnauthorized) {
		log.Println("[sync] Permission/session rejected (401/403), refreshing token and retrying...")
		s.clearToken()
		if err := s.refreshToken(); err != nil {
			return err
		}
		return s.fetchAndSave(ctx, s.getCachedToken())
	}

	return err
}

// Нећемо да издркавамо, букв одјебемо што пре да не би попили банану
func (s *InventoryService) syncWithBackoff(ctx context.Context) error {
	deadline := time.Now().Add(s.cfg.MaxFailureTime)
	backoff := s.cfg.InitialBackoff

	for attempt := 1; ; attempt++ {
		err := s.syncAttempt(ctx)
		if err == nil {
			log.Println("[sync] Inventory updated (inventory.json)")
			return nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("sync failed continuously for %s (last error: %w)", s.cfg.MaxFailureTime, err)
		}

		wait := min(backoff, remaining)
		log.Printf("[sync] Attempt %d failed: %v — retrying in %s (timeout in %s)",
			attempt, err, wait.Round(time.Second), remaining.Round(time.Second))

		if !sleepCtx(ctx, wait) {
			return ctx.Err()
		}

		backoff = min(backoff*2, s.cfg.MaxBackoff)
	}
}

func (s *InventoryService) Run(ctx context.Context) error {
	if err := s.syncWithBackoff(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.syncWithBackoff(ctx); err != nil {
				return err
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func main() {
	interval := flag.Duration("interval", 5*time.Minute, "Inventory refresh interval (e.g. 30s, 2m, 5m)")
	maxFail := flag.Duration("max-fail", 10*time.Minute, "Exit with error after failing continuously for this duration")
	outDir := flag.String("out", ".", "Directory to write inventory.json")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc := NewInventoryService(ServiceConfig{
		Interval:       *interval,
		MaxFailureTime: *maxFail,
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     1 * time.Minute,
		OutputDir:      *outDir,
	})

	log.Printf("[service] Starting Warframe inventory sync (interval=%s, max-fail=%s, out=%s)",
		*interval, *maxFail, *outDir)

	if err := svc.Run(ctx); err != nil {
		log.Printf("[service] Fatal error: %v", err)
		os.Exit(1)
	}

	log.Println("[service] Shutting down cleanly")
}
