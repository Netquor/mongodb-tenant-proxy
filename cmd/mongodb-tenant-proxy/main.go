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

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

const usage = `usage:
  mongodb-tenant-proxy [serve] -config proxy.json [-listen :27018]
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
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	srv, err := proxy.New(cfg, log)
	if err != nil {
		return err
	}
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
	if cfg.MetricsAddr != "" {
		go func() {
			if err := http.ListenAndServe(cfg.MetricsAddr, srv.M.Handler()); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("listening", "addr", ln.Addr().String(), "auth", cfg.Auth.Mode, "tenantField", cfg.Tenant.Field)
	return srv.Serve(ctx, ln)
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
