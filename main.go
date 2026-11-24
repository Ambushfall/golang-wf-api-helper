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
	authzPattern          = regexp.MustCompile(`\?accountId=([0-9a-fA-F]{24})&nonce=(\d+)`)
	errUnauthorized       = errors.New("session unauthorized or expired")
	errWarframeNotRunning = errors.New("warframe process not running")
)

type ServiceConfig struct {
	Interval       time.Duration
	ProcessPoll    time.Duration
	WaitForProcess bool
	OutputDir      string
}

type cachedSession struct {
	pid   uint32
	addr  uintptr
	authz string
}

type InventoryService struct {
	cfg    ServiceConfig
	client *http.Client

	mu      sync.Mutex
	session cachedSession
}

func NewInventoryService(cfg ServiceConfig) *InventoryService {
	return &InventoryService{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// verifyCachedSession checks that the PID hasn't changed and that the exact authz string
// still resides at the recorded virtual address.
func (s *InventoryService) verifyCachedSession(currentPID uint32) (string, bool) {
	s.mu.Lock()
	sess := s.session
	s.mu.Unlock()

	if sess.pid != currentPID || sess.addr == 0 || sess.authz == "" {
		return "", false
	}

	raw, err := readProcessMemoryAt(sess.pid, sess.addr, len(sess.authz))
	if err != nil || string(raw) != sess.authz {
		log.Println("[auth] Cached key at recorded address changed or became unreadable; rescanning...")
		s.clearSession()
		return "", false
	}

	return sess.authz, true
}

func (s *InventoryService) clearSession() {
	s.mu.Lock()
	s.session = cachedSession{}
	s.mu.Unlock()
}

func (s *InventoryService) scanForSession(pid uint32) (string, error) {
	candidates := make(map[string]int)
	var foundAuthz string
	var foundAddr uintptr

	err := scanProcessMemory(pid, func(baseAddr uintptr, chunk []byte) bool {
		for _, idx := range authzPattern.FindAllSubmatchIndex(chunk, -1) {
			candidate := string(chunk[idx[0]:idx[1]])
			candidates[candidate]++
			if candidates[candidate] == 3 {
				foundAuthz = candidate
				foundAddr = baseAddr + uintptr(idx[0])
				return true
			}
		}
		return false
	})
	if err != nil {
		return "", fmt.Errorf("memory scan failed: %w", err)
	}
	if foundAuthz == "" {
		return "", fmt.Errorf("auth token not found in process memory yet")
	}

	s.mu.Lock()
	s.session = cachedSession{
		pid:   pid,
		addr:  foundAddr,
		authz: foundAuthz,
	}
	s.mu.Unlock()

	log.Printf("[auth] Acquired session token at 0x%x (PID %d)", foundAddr, pid)
	return foundAuthz, nil
}

func (s *InventoryService) fetchAndSave(ctx context.Context, authz string) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.warframe.com/api/inventory.php"+authz,
		nil,
	)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Warframe/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusConflict {
		return errUnauthorized
	}
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

// syncOnce verifies the cached address (or scans if missing/changed) and performs a single fetch.
// On 401/403/409, it performs at most one fresh scan + retry before waiting for the next interval.
func (s *InventoryService) syncOnce(ctx context.Context) error {
	pid, err := findWarframePID()
	if err != nil {
		s.clearSession()
		return errWarframeNotRunning
	}

	authz, ok := s.verifyCachedSession(pid)
	if !ok {
		authz, err = s.scanForSession(pid)
		if err != nil {
			// Game is running (e.g. still on login screen) — skip API call until next interval
			log.Printf("[sync] Skipping fetch: %v", err)
			return nil
		}
	}

	err = s.fetchAndSave(ctx, authz)
	if errors.Is(err, errUnauthorized) {
		log.Println("[sync] Session rejected by API, rescanning once...")
		s.clearSession()
		freshAuthz, scanErr := s.scanForSession(pid)
		if scanErr != nil {
			log.Printf("[sync] Rescan failed: %v", scanErr)
			return nil
		}
		if retryErr := s.fetchAndSave(ctx, freshAuthz); retryErr != nil {
			log.Printf("[sync] Fetch after rescan failed: %v", retryErr)
			return nil
		}
		log.Println("[sync] Inventory updated (inventory.json)")
		return nil
	}

	if err != nil {
		log.Printf("[sync] Fetch failed: %v", err)
		return nil
	}

	log.Println("[sync] Inventory updated (inventory.json)")
	return nil
}

func (s *InventoryService) waitForWarframe(ctx context.Context) error {
	log.Printf("[service] Waiting for Warframe process (checking every %s)...", s.cfg.ProcessPoll)
	ticker := time.NewTicker(s.cfg.ProcessPoll)
	defer ticker.Stop()

	for {
		if _, err := findWarframePID(); err == nil {
			log.Println("[service] Warframe process detected")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *InventoryService) Run(ctx context.Context) error {
	if _, err := findWarframePID(); err != nil {
		if !s.cfg.WaitForProcess {
			return errWarframeNotRunning
		}
		if err := s.waitForWarframe(ctx); err != nil {
			return err
		}
	}

	if err := s.syncOnce(ctx); errors.Is(err, errWarframeNotRunning) && !s.cfg.WaitForProcess {
		return err
	}

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := s.syncOnce(ctx)
			if errors.Is(err, errWarframeNotRunning) {
				if !s.cfg.WaitForProcess {
					return err
				}
				if err := s.waitForWarframe(ctx); err != nil {
					return err
				}
				_ = s.syncOnce(ctx)
			}
		}
	}
}

func main() {
	interval := flag.Duration("interval", 5*time.Minute, "Inventory refresh interval (e.g. 30s, 2m, 5m)")
	wait := flag.Bool("wait", false, "Wait for Warframe to start/restart instead of exiting early when not running")
	poll := flag.Duration("poll", 10*time.Second, "Process check interval when -wait is enabled")
	outDir := flag.String("out", ".", "Directory to write inventory.json")
	version := flag.Bool("version", false, "Print version information and exit")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		bin := filepath.Base(os.Args[0])
		fmt.Fprintf(out, "warframe-api-helper — Periodic Warframe inventory sync service\n\n")
		fmt.Fprintf(out, "Usage:\n  %s [flags]\n\n", bin)
		fmt.Fprintf(out, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(out, "\nExamples:\n")
		fmt.Fprintf(out, "  %s -interval 3m -out ./data\n", bin)
		fmt.Fprintf(out, "  %s -wait -interval 5m -poll 15s\n\n", bin)
		fmt.Fprintf(out, "Exit Codes:\n")
		fmt.Fprintf(out, "  0  Clean shutdown (SIGINT / SIGTERM)\n")
		fmt.Fprintf(out, "  1  Warframe process not running (when -wait is false)\n")
		fmt.Fprintf(out, "  2  Invalid CLI flags\n")
	}

	flag.Parse()

	if *version {
		fmt.Println("warframe-api-helper v0.2.0")
		os.Exit(0)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc := NewInventoryService(ServiceConfig{
		Interval:       *interval,
		ProcessPoll:    *poll,
		WaitForProcess: *wait,
		OutputDir:      *outDir,
	})

	log.Printf("[service] Starting Warframe inventory sync (interval=%s, wait=%v, out=%s)",
		*interval, *wait, *outDir)

	if err := svc.Run(ctx); err != nil {
		log.Printf("[service] Exiting: %v", err)
		os.Exit(1)
	}

	log.Println("[service] Shutting down cleanly")
}
