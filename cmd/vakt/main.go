package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stormlimitless/vakt/internal/admin"
	"github.com/stormlimitless/vakt/internal/auth"
	"github.com/stormlimitless/vakt/internal/config"
	"github.com/stormlimitless/vakt/internal/proxy"
	"github.com/stormlimitless/vakt/internal/store"
	"github.com/stormlimitless/vakt/internal/tlsconf"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("vakt", version)
		return
	}
	defaultCfg := os.Getenv("VAKT_CONFIG")
	if defaultCfg == "" {
		defaultCfg = config.Default().DataDir + "/vakt.yaml"
	}
	cfgPath := flag.String("config", defaultCfg, "path to vakt.yaml")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		log.Fatal(err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := cfg.ApplySites(st); err != nil {
		return err
	}
	cipher, err := auth.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return err
	}
	sessions := &auth.Sessions{Store: st}
	lockout := &auth.Lockout{Store: st, MaxAttempts: cfg.Lockout.MaxAttempts, Duration: time.Duration(cfg.Lockout.Minutes) * time.Minute}
	trusted := proxy.ParseCIDRs(cfg.TrustedProxies)
	secure := cfg.TLS.Mode != "off"

	adm := &admin.Admin{Store: st, Sessions: sessions, Lockout: lockout, Cipher: cipher, Trusted: trusted, Secure: secure, Version: version}
	gw := &proxy.Gateway{Store: st, Sessions: sessions, Lockout: lockout, Cipher: cipher, Trusted: trusted, Secure: secure, Admin: adm.Handler(), AdminHost: cfg.AdminHost}

	setupPath, err := adm.EnsureSetupToken()
	if err != nil {
		return err
	}
	if setupPath != "" {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		log.Printf("no admin user yet: open %s://%s%s within 1 hour to create one", scheme, cfg.AdminHost, setupPath)
	}

	sites, err := st.ListSites()
	if err != nil {
		return err
	}
	hosts := []string{cfg.AdminHost}
	for _, s := range sites {
		hosts = append(hosts, s.Host)
	}
	tlsCfg, httpHandler, err := tlsconf.Build(cfg.TLS, cfg.DataDir, hosts, gw.Handler())
	if err != nil {
		return err
	}

	go func() {
		for range time.Tick(10 * time.Minute) {
			if err := st.PurgeExpiredSessions(); err != nil {
				log.Printf("purge sessions: %v", err)
			}
		}
	}()

	httpSrv := &http.Server{Addr: cfg.ListenHTTP, Handler: httpHandler, ReadHeaderTimeout: 10 * time.Second}
	servers := []*http.Server{httpSrv}
	errCh := make(chan error, 2)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	log.Printf("vakt %s listening on %s", version, cfg.ListenHTTP)
	if tlsCfg != nil {
		httpsSrv := &http.Server{Addr: cfg.ListenHTTPS, Handler: gw.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, httpsSrv)
		go func() { errCh <- httpsSrv.ListenAndServeTLS("", "") }()
		log.Printf("tls (%s) listening on %s", cfg.TLS.Mode, cfg.ListenHTTPS)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(ctx)
	}
	return nil
}
