// Package clientip determines the address of the client that originated an
// HTTP request, taking trusted reverse proxies into account.
//
// X-Forwarded-For is only consulted when the direct TCP peer is a trusted
// proxy. The header is then walked from the right (the hop added by the proxy
// closest to us) towards the left, and the first address that is not itself a
// trusted proxy is the client. Everything further left was supplied by that
// untrusted client and is ignored, so a client cannot spoof its address by
// sending its own X-Forwarded-For header.
package clientip

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

var (
	// ErrInvalidRemoteAddr means the TCP peer address could not be parsed.
	ErrInvalidRemoteAddr = errors.New("invalid remote address")
	// ErrMalformedForwardedFor means a trusted proxy chain contained an entry
	// that is not a plain IP address, so the client cannot be determined.
	ErrMalformedForwardedFor = errors.New("malformed X-Forwarded-For header")
)

const forwardedForHeader = "X-Forwarded-For"

// Resolver resolves client addresses. The zero value trusts no proxies.
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver returns a Resolver that trusts forwarding information only from
// peers inside trustedProxies.
func NewResolver(trustedProxies []netip.Prefix) *Resolver {
	return &Resolver{trusted: trustedProxies}
}

// Resolve returns the originating client address and the direct TCP peer
// address of req. Returned addresses are unmapped and zone-free, so IPv4
// clients reaching a dual-stack listener compare equal to IPv4 networks.
func (r *Resolver) Resolve(req *http.Request) (client, peer netip.Addr, err error) {
	ap, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, ErrInvalidRemoteAddr
	}
	peer = normalize(ap.Addr())
	if !r.isTrusted(peer) {
		// Forwarding headers from untrusted peers are ignored entirely.
		return peer, peer, nil
	}

	client = peer
	values := req.Header.Values(forwardedForHeader)
	for i := len(values) - 1; i >= 0; i-- {
		line := values[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		for {
			var entry string
			idx := strings.LastIndexByte(line, ',')
			if idx < 0 {
				entry = line
			} else {
				entry, line = line[idx+1:], line[:idx]
			}
			addr, perr := netip.ParseAddr(strings.TrimSpace(entry))
			if perr != nil {
				// This entry was written by a trusted proxy (every hop to its
				// right is trusted), so the chain is broken and we cannot
				// tell who the client is. Fail closed.
				return netip.Addr{}, peer, ErrMalformedForwardedFor
			}
			client = normalize(addr)
			if !r.isTrusted(client) {
				return client, peer, nil
			}
			if idx < 0 {
				break
			}
		}
	}
	// Every hop was a trusted proxy: the leftmost one originated the request,
	// or the peer itself did if there was no header.
	return client, peer, nil
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func normalize(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}
