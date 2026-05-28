// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// DPM replacement main.go for rdpgw.
// Strips out OIDC/Kerberos/NTLM auth from upstream, uses DPM webhook
// token validation instead. Keeps the core RD Gateway protocol handler.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NISP-GmbH/rdpgw-fork/cmd/rdpgw/protocol"
	"github.com/NISP-GmbH/rdpgw-fork/cmd/rdpgw/security"
	"github.com/NISP-GmbH/rdpgw-fork/cmd/rdpgw/web"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	flags "github.com/thought-machine/go-flags"
	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	CertFile             string   `yaml:"certFile"`
	KeyFile              string   `yaml:"keyFile"`
	GatewayAddress       string   `yaml:"gatewayAddress"`
	Hosts                []string `yaml:"hosts"`
	HostSelection        string   `yaml:"hostSelection"`
	SessionKey           string   `yaml:"sessionKey"`
	SessionEncryptionKey string   `yaml:"sessionEncryptionKey"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey string `yaml:"paaTokenEncryptionKey"`
	PAATokenSigningKey    string `yaml:"paaTokenSigningKey"`
	EnableUserToken       bool   `yaml:"enableUserToken"`
}

type Configuration struct {
	Server   ServerConfig  `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	DPM      DPMConfig     `yaml:"dpm"`
	API      DPMAPIConfig  `yaml:"api"`
	Logging  LoggingConfig `yaml:"logging"`
}

var opts struct {
	ConfigFile string `short:"c" long:"conf" default:"/etc/dpm/rdpgw-config.yaml" description:"config file (yaml)"`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	data, err := os.ReadFile(opts.ConfigFile)
	if err != nil {
		log.Fatalf("Cannot read config %s: %s", opts.ConfigFile, err)
	}
	var conf Configuration
	if err := yaml.Unmarshal(data, &conf); err != nil {
		log.Fatalf("Cannot parse config: %s", err)
	}

	if len(conf.Server.Hosts) == 0 {
		log.Fatal("Not enough hosts to connect to specified")
	}

	// Security keys (required by upstream's security package)
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.HostSelection = conf.Server.HostSelection
	security.Hosts = conf.Server.Hosts

	// Session store
	web.InitStore(
		[]byte(conf.Server.SessionKey),
		[]byte(conf.Server.SessionEncryptionKey),
		"cookie",
		0,
	)

	// Initialize DPM integration
	var dpmInteg *DPMIntegration
	dpmCfg := DPMFullConfig{
		DPM:     conf.DPM,
		API:     conf.API,
		Logging: conf.Logging,
	}
	dpmInteg = InitDPMIntegration(dpmCfg)

	// Gateway protocol handler
	gw := protocol.Gateway{
		TokenAuth:   true,
		IdleTimeout: 0,
		CheckPAACookie: func(ctx context.Context, token string) (bool, error) {
			log.Printf("[DPM-PAA] CheckPAACookie called, token length=%d", len(token))
			if dpmInteg != nil && dpmInteg.Auth != nil {
				log.Printf("[DPM-PAA] Validating token via DPM backend")
				resp, vErr := dpmInteg.Auth.ValidateToken(token, "")
				if vErr != nil {
					log.Printf("[DPM-PAA] Token validation failed: %v", vErr)
					dpmRecordAuthFailure("token_rejected")
					return false, vErr
				}
				log.Printf("[DPM-PAA] Token validated: user=%s server=%s session=%s",
					resp.Username, resp.Host, resp.SessionID)

				if t, ok := ctx.Value(protocol.CtxTunnel).(*protocol.Tunnel); ok && t != nil {
					t.TargetServer = fmt.Sprintf("%s:%d", resp.Host, resp.Port)
					if t.User != nil {
						t.User.SetUserName(resp.Username)
					}
					log.Printf("[DPM-PAA] Tunnel target set to %s", t.TargetServer)
				}

				dpmInteg.OnSessionConnected(&DPMSessionInfo{
					SessionID:    resp.SessionID,
					Username:     resp.Username,
					TargetServer: resp.Host,
					ConnectedAt:  time.Now(),
					LastSeen:     time.Now(),
				})
				return true, nil
			}
			return security.CheckPAACookie(ctx, token)
		},
		CheckHost: func(ctx context.Context, host string) (bool, error) {
			log.Printf("[DPM-HOST] CheckHost called for: %s", host)
			return true, nil
		},
	}

	// Router
	r := mux.NewRouter()
	if dpmInteg != nil {
		r.Use(DPMTokenAuthContext)
	} else {
		r.Use(web.EnrichContext)
	}
	r.Handle("/metrics", promhttp.Handler())
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.PathPrefix("/remoteDesktopGateway/").HandlerFunc(gw.HandleGatewayProtocol)

	// TLS
	addr := conf.Server.GatewayAddress
	if addr == "" {
		addr = ":8389"
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if conf.Server.CertFile != "" && conf.Server.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
		if err != nil {
			log.Fatalf("Cannot load TLS cert/key: %s", err)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	} else {
		log.Fatal("TLS certificate and key are required")
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   r,
		TLSConfig: cfg,
	}

	log.Printf("rdpgw starting on %s (hosts=%v, dpm=%v)", addr, conf.Server.Hosts, dpmInteg != nil)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}
