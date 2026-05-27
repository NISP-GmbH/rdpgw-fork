// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// DPM integration bootstrap — wires DPM auth, session store, API server,
// and metrics into the rdpgw lifecycle.
//
// Integration points in upstream rdpgw code:
//   - process.go: handshake -> call dpmAuth.ValidateToken(paaToken, clientIP)
//   - gateway.go: channel close -> call OnSessionDisconnected(sessionID, reason)
//   - tunnel.go:  Read/Write -> call sessionStore.UpdateBytes()

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

type DPMIntegration struct {
	Auth         *DPMAuthenticator
	SessionStore *DPMSessionStore
	APIHandler   *DPMAPIHandler
	Logger       *slog.Logger
}

type DPMFullConfig struct {
	DPM     DPMConfig    `yaml:"DPM"`
	API     DPMAPIConfig `yaml:"API"`
	Logging LoggingConfig `yaml:"Logging"`
}

type LoggingConfig struct {
	Format string `yaml:"Format"`
	Level  string `yaml:"Level"`
}

func InitDPMIntegration(cfg DPMFullConfig) *DPMIntegration {
	logger := initDPMLogger(cfg.Logging)

	if cfg.DPM.CredentialsFile != "" {
		loadCredentialsFile(&cfg.DPM, logger)
	}

	if !cfg.DPM.Enabled {
		logger.Info("dpm_integration_disabled")
		return nil
	}

	dpmAuth := NewDPMAuthenticator(cfg.DPM, logger)
	sessionStore := NewDPMSessionStore(logger)
	apiHandler := NewDPMAPIHandler(sessionStore, nil, cfg.API, logger)
	apiHandler.StartAPIServer()

	logger.Info("dpm_integration_initialized",
		"validate_url", cfg.DPM.ValidateTokenURL,
		"session_notify_url", cfg.DPM.SessionNotifyURL,
		"api_addr", cfg.API.Addr,
	)

	return &DPMIntegration{
		Auth:         dpmAuth,
		SessionStore: sessionStore,
		APIHandler:   apiHandler,
		Logger:       logger,
	}
}

func (d *DPMIntegration) OnSessionConnected(info *DPMSessionInfo) {
	d.SessionStore.Add(info)
	dpmRecordSessionStart()
	d.Logger.Info("session_connected",
		"session_id", info.SessionID,
		"username", info.Username,
		"target", info.TargetServer,
		"client_ip", info.ClientIP,
	)
}

func (d *DPMIntegration) OnSessionDisconnected(sessionID string, reason string) {
	info := d.SessionStore.Remove(sessionID)
	if info == nil {
		return
	}

	duration := time.Since(info.ConnectedAt)
	dpmRecordSessionEnd(duration.Seconds(), info.BytesSent, info.BytesReceived)

	d.Auth.NotifySessionEvent(SessionNotifyRequest{
		SessionID:     sessionID,
		Event:         "disconnected",
		Reason:        reason,
		BytesSent:     info.BytesSent,
		BytesReceived: info.BytesReceived,
		DurationSecs:  int64(duration.Seconds()),
		ClientIP:      info.ClientIP,
		TargetServer:  info.TargetServer,
	})

	d.Logger.Info("session_disconnected",
		"session_id", sessionID,
		"username", info.Username,
		"duration_s", int64(duration.Seconds()),
		"bytes_sent", info.BytesSent,
		"bytes_received", info.BytesReceived,
		"reason", reason,
	)
}

func (d *DPMIntegration) SetDisconnectFunc(fn DisconnectFunc) {
	d.APIHandler = NewDPMAPIHandler(d.SessionStore, fn, d.APIHandler.config, d.Logger)
}

func initDPMLogger(cfg LoggingConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

func loadCredentialsFile(cfg *DPMConfig, logger *slog.Logger) {
	data, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		logger.Warn("credentials_file_read_error", "path", cfg.CredentialsFile, "error", err)
		return
	}
	var creds struct {
		BackendURL        string `json:"backend_url"`
		ValidateTokenPath string `json:"validate_token_path"`
		SessionNotifyPath string `json:"session_notify_path"`
		AuthUser          string `json:"auth_user"`
		AuthPass          string `json:"auth_pass"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		logger.Warn("credentials_file_parse_error", "error", err)
		return
	}
	if creds.AuthUser != "" {
		cfg.AuthUsername = creds.AuthUser
	}
	if creds.AuthPass != "" {
		cfg.AuthPassword = creds.AuthPass
	}
	if creds.BackendURL != "" && creds.ValidateTokenPath != "" {
		cfg.ValidateTokenURL = creds.BackendURL + creds.ValidateTokenPath
	}
	if creds.BackendURL != "" && creds.SessionNotifyPath != "" {
		cfg.SessionNotifyURL = creds.BackendURL + creds.SessionNotifyPath
	}
	logger.Info("credentials_loaded_from_file", "path", cfg.CredentialsFile)
}
