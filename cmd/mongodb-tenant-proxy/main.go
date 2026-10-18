// Command mongodb-tenant-proxy is a MongoDB wire-protocol proxy that confines
// every connection to a single tenant's documents.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/admin"
	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

// Set at build time: -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `usage:
  mongodb-tenant-proxy [serve] -config proxy.json [-listen :27018]
  mongodb-tenant-proxy version
  mongodb-tenant-proxy healthcheck [-config proxy.json | -url http://127.0.0.1:9102/healthz]
  mongodb-tenant-proxy hash-password -user NAME -tenant TENANT   (password read from $MTP_PASSWORD or stdin prompt)
  mongodb-tenant-proxy sign-appname -secret SECRET -tenant TENANT
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "version":
		fmt.Printf("mongodb-tenant-proxy %s (commit %s, built %s)\n", version, commit, date)
	case "healthcheck":
		err = healthcheck(args)
	case "hash-password":
		err = hashPassword(args)
	case "sign-appname":
		err = signAppName(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "path to JSON config file")
	listen := fs.String("listen", "", "override listen address")
	fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	lv := new(slog.LevelVar)
	lv.Set(cfg.SlogLevel())
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	srv, err := proxy.New(cfg, log)
	if err != nil {
		return err
	}
	srv.OnReload(func(c *config.Config) { lv.Set(c.SlogLevel()) })
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if t := cfg.ClientTLS; t != nil {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var hs []*http.Server
	if cfg.MetricsAddr != "" {
		hs = append(hs, &http.Server{Addr: cfg.MetricsAddr, Handler: srv.M.Handler(), ReadHeaderTimeout: 10 * time.Second})
	}
	if cfg.AdminAddr != "" {
		adm, err := admin.New(srv, cfg.Admin)
		if err != nil {
			return err
		}
		aln, err := net.Listen("tcp", cfg.AdminAddr)
		if err != nil {
			return err
		}
		go func() {
			if err := adm.Serve(ctx, aln); err != nil {
				log.Error("admin server", "err", err)
			}
		}()
		log.Info("admin API listening", "addr", aln.Addr().String(), "tls", cfg.Admin.TLS != nil)
	}
	for _, h := range hs {
		h := h
		go func() {
			if err := h.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server", "err", err)
			}
		}()
	}

	// SIGHUP reloads the config file; an invalid file leaves the old config running.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if _, err := srv.Reload(); err != nil {
				log.Error("config reload failed; keeping previous config", "err", err)
			}
		}
	}()

	log.Info("listening", "addr", ln.Addr().String(), "auth", cfg.Auth.Mode, "tenantField", cfg.Tenant.Field, "version", version)
	err = srv.Serve(ctx, ln)
	for _, h := range hs {
		h.Close()
	}
	return err
}

func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	path := fs.String("config", "", "config file to read metricsAddr from")
	u := fs.String("url", os.Getenv("MTP_HEALTH_URL"), "health URL")
	fs.Parse(args)
	if *u == "" {
		addr := "127.0.0.1:9102"
		if *path != "" {
			cfg, err := config.Load(*path)
			if err != nil {
				return err
			}
			if cfg.MetricsAddr == "" {
				return fmt.Errorf("metricsAddr is not set in %s", *path)
			}
			addr = cfg.MetricsAddr
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		*u = "http://" + net.JoinHostPort(host, port) + "/healthz"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(*u)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}

func hashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
	user := fs.String("user", "", "username")
	tenant := fs.String("tenant", "", "tenant id the user is bound to")
	fs.Parse(args)
	pw := os.Getenv("MTP_PASSWORD")
	if pw == "" {
		return fmt.Errorf("set MTP_PASSWORD in the environment")
	}
	if *user == "" || *tenant == "" {
		return fmt.Errorf("-user and -tenant are required")
	}
	u, err := auth.NewUser(*user, *tenant, pw)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(u)
}

func signAppName(args []string) error {
	fs := flag.NewFlagSet("sign-appname", flag.ExitOnError)
	secret := fs.String("secret", os.Getenv("MTP_APPNAME_SECRET"), "shared secret")
	tenant := fs.String("tenant", "", "tenant id")
	fs.Parse(args)
	if *secret == "" || *tenant == "" {
		return fmt.Errorf("-secret and -tenant are required")
	}
	fmt.Println(auth.SignTenant(*secret, *tenant))
	return nil
}
