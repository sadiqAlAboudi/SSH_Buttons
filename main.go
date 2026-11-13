package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPathFlag := flag.String("config", "config.yml", "Path to YAML configuration file")
	portFlag := flag.Int("port", 0, "HTTP listen port (overrides default 8080)")
	flag.Parse()

	configPath := *configPathFlag
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}

	log.Printf("[INFO] Loading configuration from %s...", configPath)
	configMgr, err := NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("[FATAL] Could not initialize configuration: %v", err)
	}

	cfg := configMgr.Get()
	if *portFlag > 0 {
		cfg.Server.Port = *portFlag
	}
	log.Printf("[INFO] Config loaded successfully: %d hosts, %d buttons configured", len(cfg.Hosts), len(cfg.ButtonsByID))

	server, err := NewServer(configMgr)
	if err != nil {
		log.Fatalf("[FATAL] Could not initialize web server: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      SecurityHeadersMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Server run context for graceful shutdown
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		log.Println("[INFO] Shutdown signal received, gracefully terminating...")

		// Shutdown signal with grace period of 15 seconds
		shutdownCtx, shutdownCancel := context.WithTimeout(serverCtx, 15*time.Second)
		defer shutdownCancel()

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("[FATAL] Graceful shutdown timed out.. forcing exit.")
			}
		}()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("[FATAL] Server shutdown error: %v", err)
		}
		serverStopCtx()
	}()

	log.Printf("[INFO] SSH Buttons dashboard running at http://0.0.0.0:%d (%d users, %d hosts)", cfg.Server.Port, len(cfg.Users), len(cfg.Hosts))
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FATAL] HTTP server failed to listen: %v", err)
	}

	// Wait for server context to stop
	<-serverCtx.Done()
	log.Println("[INFO] Server stopped cleanly.")
}
