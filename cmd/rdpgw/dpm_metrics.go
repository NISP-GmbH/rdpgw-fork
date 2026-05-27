// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// Enhanced Prometheus metrics for DPM rdpgw fork.

package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	dpmSessionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rdpgw_sessions_total",
		Help: "Total number of RDP sessions started.",
	})

	dpmSessionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "rdpgw_session_duration_seconds",
		Help:    "Duration of RDP sessions in seconds.",
		Buckets: prometheus.ExponentialBuckets(60, 2, 10),
	})

	dpmBytesSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rdpgw_bytes_sent_total",
		Help: "Total bytes sent to RDP clients.",
	})

	dpmBytesReceivedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rdpgw_bytes_received_total",
		Help: "Total bytes received from RDP clients.",
	})

	dpmAuthFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rdpgw_auth_failures_total",
		Help: "Total authentication failures by reason.",
	}, []string{"reason"})

	dpmActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rdpgw_dpm_active_sessions",
		Help: "Current number of active RDP sessions tracked by DPM.",
	})
)

func dpmRecordSessionStart() {
	dpmSessionsTotal.Inc()
	dpmActiveSessions.Inc()
}

func dpmRecordSessionEnd(durationSecs float64, bytesSent, bytesReceived int64) {
	dpmActiveSessions.Dec()
	dpmSessionDuration.Observe(durationSecs)
	dpmBytesSentTotal.Add(float64(bytesSent))
	dpmBytesReceivedTotal.Add(float64(bytesReceived))
}

func dpmRecordAuthFailure(reason string) {
	dpmAuthFailuresTotal.WithLabelValues(reason).Inc()
}
