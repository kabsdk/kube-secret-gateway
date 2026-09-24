package clientip

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

func TestResolve(t *testing.T) {
	resolver := NewResolver([]netip.Prefix{
		netip.MustParsePrefix("10.42.0.0/16"),
		netip.MustParsePrefix("fd00:42::/64"),
	})

	cases := []struct {
		name       string
		remoteAddr string
		xff        []string
		wantClient string
		wantPeer   string
		wantErr    error
	}{
		{
			name:       "direct client with no proxy",
			remoteAddr: "10.10.30.40:52100",
			wantClient: "10.10.30.40",
			wantPeer:   "10.10.30.40",
		},
		{
			name:       "direct client sending spoofed X-Forwarded-For",
			remoteAddr: "203.0.113.9:40000",
			xff:        []string{"10.10.30.40"},
			wantClient: "203.0.113.9",
			wantPeer:   "203.0.113.9",
		},
		{
			name:       "X-Forwarded-For ignored from untrusted peer even when malformed",
			remoteAddr: "203.0.113.9:40000",
			xff:        []string{"not-an-ip, 10.10.30.40"},
			wantClient: "203.0.113.9",
			wantPeer:   "203.0.113.9",
		},
		{
			name:       "trusted proxy with one forwarded address",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40"},
			wantClient: "10.10.30.40",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "trusted proxy chain",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40, 10.42.7.7, 10.42.9.9"},
			wantClient: "10.10.30.40",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "client-supplied entries left of the first untrusted hop are ignored",
			remoteAddr: "10.42.1.5:8000",
			// The client sent "10.10.30.40" itself; the proxy appended the
			// real address 198.51.100.7.
			xff:        []string{"10.10.30.40, 198.51.100.7"},
			wantClient: "198.51.100.7",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "trusted and untrusted proxy combination",
			remoteAddr: "10.42.1.5:8000",
			// An untrusted proxy (192.0.2.1) sits between the client and our
			// trusted proxies; it is the furthest hop we can vouch for.
			xff:        []string{"10.10.30.40, 192.0.2.1, 10.42.3.3"},
			wantClient: "192.0.2.1",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "multiple header lines are one list",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40", "10.42.3.3"},
			wantClient: "10.10.30.40",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "every hop trusted yields the leftmost",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.42.8.8, 10.42.3.3"},
			wantClient: "10.42.8.8",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "trusted proxy without forwarded header",
			remoteAddr: "10.42.1.5:8000",
			wantClient: "10.42.1.5",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "trusted proxy with blank forwarded header",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"  "},
			wantClient: "10.42.1.5",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "malformed forwarded address",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40, bogus"},
			wantPeer:   "10.42.1.5",
			wantErr:    ErrMalformedForwardedFor,
		},
		{
			name:       "forwarded address with port is malformed",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40:1234"},
			wantPeer:   "10.42.1.5",
			wantErr:    ErrMalformedForwardedFor,
		},
		{
			name:       "empty entry in chain is malformed",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"10.10.30.40,,10.42.3.3"},
			wantPeer:   "10.42.1.5",
			wantErr:    ErrMalformedForwardedFor,
		},
		{
			name:       "malformed entry beyond the first untrusted hop is never parsed",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"garbage, 10.10.30.40"},
			wantClient: "10.10.30.40",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "IPv4 peer as IPv4-mapped IPv6",
			remoteAddr: "[::ffff:10.10.30.40]:52100",
			wantClient: "10.10.30.40",
			wantPeer:   "10.10.30.40",
		},
		{
			name:       "IPv6 direct client",
			remoteAddr: "[2001:db8::10]:52100",
			xff:        []string{"2001:db8::99"},
			wantClient: "2001:db8::10",
			wantPeer:   "2001:db8::10",
		},
		{
			name:       "IPv6 trusted proxy forwarding IPv6 client",
			remoteAddr: "[fd00:42::5]:8000",
			xff:        []string{"2001:db8::10, fd00:42::7"},
			wantClient: "2001:db8::10",
			wantPeer:   "fd00:42::5",
		},
		{
			name:       "IPv6 trusted proxy forwarding IPv4 client",
			remoteAddr: "[fd00:42::5]:8000",
			xff:        []string{"10.10.30.40"},
			wantClient: "10.10.30.40",
			wantPeer:   "fd00:42::5",
		},
		{
			name:       "IPv4-mapped forwarded address is unmapped",
			remoteAddr: "10.42.1.5:8000",
			xff:        []string{"::ffff:10.10.30.40"},
			wantClient: "10.10.30.40",
			wantPeer:   "10.42.1.5",
		},
		{
			name:       "zone is stripped",
			remoteAddr: "[fe80::1%eth0]:8000",
			wantClient: "fe80::1",
			wantPeer:   "fe80::1",
		},
		{
			name:       "unparseable remote address",
			remoteAddr: "somewhere",
			wantErr:    ErrInvalidRemoteAddr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			client, peer, err := resolver.Resolve(req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && client.String() != tc.wantClient {
				t.Errorf("client = %s, want %s", client, tc.wantClient)
			}
			if tc.wantErr != nil && client.IsValid() {
				t.Errorf("client = %s on error, want invalid address", client)
			}
			if tc.wantPeer != "" && peer.String() != tc.wantPeer {
				t.Errorf("peer = %s, want %s", peer, tc.wantPeer)
			}
		})
	}
}

func TestNoTrustedProxies(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.42.1.5:8000"
	req.Header.Set("X-Forwarded-For", "10.10.30.40")
	client, _, err := (&Resolver{}).Resolve(req)
	if err != nil || client.String() != "10.42.1.5" {
		t.Fatalf("got %s, %v; want the TCP peer when no proxy is trusted", client, err)
	}
}
