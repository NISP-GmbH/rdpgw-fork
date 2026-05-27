// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// DPM webhook authenticator for rdpgw.
// Validates gateway access tokens against the DPM backend API.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type DPMConfig struct {
	Enabled          bool   `yaml:"Enabled"`
	ValidateTokenURL string `yaml:"ValidateTokenURL"`
	SessionNotifyURL string `yaml:"SessionNotifyURL"`
	AuthUsername      string `yaml:"AuthUsername"`
	AuthPassword     string `yaml:"AuthPassword"`
	CredentialsFile  string `yaml:"CredentialsFile"`
}

type ValidateRequest struct {
	Token    string `json:"token"`
	ClientIP string `json:"client_ip"`
}

type ValidateResponse struct {
	Allowed   bool   `json:"allowed"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SessionID string `json:"session_id"`
	Username  string `json:"username"`
	Reason    string `json:"reason,omitempty"`
}

type SessionNotifyRequest struct {
	SessionID     string `json:"session_id"`
	Event         string `json:"event"`
	Reason        string `json:"reason,omitempty"`
	BytesSent     int64  `json:"bytes_sent,omitempty"`
	BytesReceived int64  `json:"bytes_received,omitempty"`
	DurationSecs  int64  `json:"duration_seconds,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	TargetServer  string `json:"target_server,omitempty"`
}

type DPMAuthenticator struct {
	config DPMConfig
	client *http.Client
	logger *slog.Logger
}

func NewDPMAuthenticator(config DPMConfig, logger *slog.Logger) *DPMAuthenticator {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &DPMAuthenticator{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second, Transport: tr},
		logger: logger,
	}
}

func (a *DPMAuthenticator) ValidateToken(token string, clientIP string) (*ValidateResponse, error) {
	reqBody := ValidateRequest{Token: token, ClientIP: clientIP}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", a.config.ValidateTokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(a.config.AuthUsername, a.config.AuthPassword)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	a.logger.Info("validate_response",
		"http_status", resp.StatusCode,
		"body_length", len(respBody),
		"body_preview", string(respBody[:min(len(respBody), 200)]),
	)

	var result ValidateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if !result.Allowed {
		a.logger.Warn("token_rejected",
			"reason", result.Reason,
			"client_ip", clientIP,
			"http_status", resp.StatusCode,
		)
		return &result, fmt.Errorf("token rejected: %s", result.Reason)
	}

	a.logger.Info("token_validated",
		"session_id", result.SessionID,
		"username", result.Username,
		"target", fmt.Sprintf("%s:%d", result.Host, result.Port),
		"client_ip", clientIP,
	)

	return &result, nil
}

func (a *DPMAuthenticator) NotifySessionEvent(notify SessionNotifyRequest) {
	body, err := json.Marshal(notify)
	if err != nil {
		a.logger.Error("session_notify_marshal_error", "error", err)
		return
	}

	req, err := http.NewRequest("POST", a.config.SessionNotifyURL, bytes.NewReader(body))
	if err != nil {
		a.logger.Error("session_notify_request_error", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(a.config.AuthUsername, a.config.AuthPassword)

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Warn("session_notify_failed", "error", err, "session_id", notify.SessionID)
		return
	}
	defer resp.Body.Close()

	a.logger.Info("session_notify_sent",
		"session_id", notify.SessionID,
		"event", notify.Event,
	)
}
