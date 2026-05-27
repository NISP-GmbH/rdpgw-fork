// Copyright 2025 - 2026 by NI SP Software GmbH, All rights reserved.
//
// This software includes confidential and proprietary information
// of NI SP Software GmbH ("Confidential Information").
// You shall not disclose such Confidential Information
// and shall use it only in accordance with the terms of
// the license agreement you entered into with NI SP Software.
////////////////////////////////////////////////////////////////////////////////

// DPM middleware for TokenAuth mode.
//
// The upstream EnrichContext middleware reads identity from a gorilla
// session cookie. RDP clients (mstsc, Microsoft Remote Desktop) do not
// send HTTP cookies, so the two connections (RDGOUT + RDGIN) that form
// a single RD Gateway session get different anonymous identities.
// The upstream HandleGatewayProtocol then rejects the second connection
// with "rejecting reuse of Rdg-Connection-Id from a different identity".
//
// This middleware replaces EnrichContext when DPM integration is active.
// It creates a deterministic identity keyed by the client IP so both
// connections from the same client match tunnelOwnerMatches. The real
// authentication happens later via CheckPAACookie (DPM webhook).

package main

import (
	"log"
	"net"
	"net/http"

	"github.com/NISP-GmbH/rdpgw-fork/cmd/rdpgw/identity"
)

func DPMTokenAuthContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}

		id := identity.NewUser()
		id.SetUserName("dpm-token-" + remoteHost)
		id.SetAttribute(identity.AttrClientIp, remoteHost)
		id.SetAttribute(identity.AttrRemoteAddr, r.RemoteAddr)

		log.Printf("[DPM-MW] %s %s from %s", r.Method, r.URL.Path, remoteHost)

		ctx := identity.AddToRequestCtx(id, r)
		next.ServeHTTP(w, ctx)
	})
}
