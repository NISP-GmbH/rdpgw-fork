// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// DPM API handlers for rdpgw — session list, force-disconnect, and health.

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type DPMSessionInfo struct {
	SessionID     string    `json:"session_id"`
	TunnelID      string    `json:"tunnel_id"`
	Username      string    `json:"username"`
	TargetServer  string    `json:"target_server"`
	ClientIP      string    `json:"client_ip"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	ConnectedAt   time.Time `json:"connected_at"`
	LastSeen      time.Time `json:"last_seen"`
	DurationSecs  int64     `json:"duration_seconds"`
}

type DPMSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*DPMSessionInfo
	logger   *slog.Logger
}

func NewDPMSessionStore(logger *slog.Logger) *DPMSessionStore {
	return &DPMSessionStore{
		sessions: make(map[string]*DPMSessionInfo),
		logger:   logger,
	}
}

func (s *DPMSessionStore) Add(info *DPMSessionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[info.SessionID] = info
}

func (s *DPMSessionStore) Remove(sessionID string) *DPMSessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
	}
	return info
}

func (s *DPMSessionStore) Get(sessionID string) *DPMSessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[sessionID]
}

func (s *DPMSessionStore) UpdateBytes(sessionID string, sent, received int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info, ok := s.sessions[sessionID]; ok {
		info.BytesSent = sent
		info.BytesReceived = received
		info.LastSeen = time.Now()
		info.DurationSecs = int64(time.Since(info.ConnectedAt).Seconds())
	}
}

func (s *DPMSessionStore) List() []*DPMSessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*DPMSessionInfo, 0, len(s.sessions))
	for _, info := range s.sessions {
		info.DurationSecs = int64(time.Since(info.ConnectedAt).Seconds())
		result = append(result, info)
	}
	return result
}

type DisconnectFunc func(tunnelID string) error

type DPMAPIConfig struct {
	Enabled      bool   `yaml:"Enabled"`
	Addr         string `yaml:"Addr"`
	AuthUsername  string `yaml:"AuthUsername"`
	AuthPassword string `yaml:"AuthPassword"`
}

type DPMAPIHandler struct {
	store      *DPMSessionStore
	disconnect DisconnectFunc
	config     DPMAPIConfig
	logger     *slog.Logger
}

func NewDPMAPIHandler(store *DPMSessionStore, disconnect DisconnectFunc, config DPMAPIConfig, logger *slog.Logger) *DPMAPIHandler {
	return &DPMAPIHandler{
		store:      store,
		disconnect: disconnect,
		config:     config,
		logger:     logger,
	}
}

func (h *DPMAPIHandler) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok || user != h.config.AuthUsername || pass != h.config.AuthPassword {
		w.Header().Set("WWW-Authenticate", `Basic realm="dpm-rdpgw"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *DPMAPIHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(w, r) {
		return
	}
	sessions := h.store.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (h *DPMAPIHandler) HandleDisconnectSession(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(w, r) {
		return
	}
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		http.Error(w, `{"error":"session_id required"}`, http.StatusBadRequest)
		return
	}
	info := h.store.Get(sessionID)
	if info == nil {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}
	if h.disconnect != nil && info.TunnelID != "" {
		if err := h.disconnect(info.TunnelID); err != nil {
			h.logger.Warn("disconnect_failed", "session_id", sessionID, "error", err)
		}
	}
	h.store.Remove(sessionID)
	h.logger.Info("session_force_disconnected", "session_id", sessionID, "username", info.Username)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (h *DPMAPIHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	sessions := h.store.List()
	resp := map[string]interface{}{
		"status":          "ok",
		"active_sessions": len(sessions),
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *DPMAPIHandler) StartAPIServer() {
	if !h.config.Enabled || h.config.Addr == "" {
		h.logger.Info("dpm_api_disabled")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/dpm/sessions", h.HandleListSessions)
	mux.HandleFunc("DELETE /api/dpm/sessions/{session_id}", h.HandleDisconnectSession)
	mux.HandleFunc("GET /api/dpm/health", h.HandleHealth)
	h.logger.Info("dpm_api_starting", "addr", h.config.Addr)
	go func() {
		if err := http.ListenAndServe(h.config.Addr, mux); err != nil {
			h.logger.Error("dpm_api_server_error", "error", err)
		}
	}()
}
