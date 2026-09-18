package exposure

import (
	"net/netip"
	"slices"
	"testing"
)

func TestKeyFilter(t *testing.T) {
	all := KeyFilter{}
	if !all.Exposes("anything") || all.Required("anything") || all.RequiredKeys() != nil {
		t.Error("zero KeyFilter must expose every key and require none")
	}

	inc := IncludeKeys("tls.crt", "tls.key", "tls.crt")
	if !inc.Exposes("tls.crt") || inc.Exposes("ca.crt") {
		t.Error("IncludeKeys exposes the wrong keys")
	}
	if !inc.Required("tls.key") || inc.Required("ca.crt") {
		t.Error("IncludeKeys must require exactly the included keys")
	}
	if got := inc.RequiredKeys(); !slices.Equal(got, []string{"tls.crt", "tls.key"}) {
		t.Errorf("RequiredKeys = %v (order kept, duplicates dropped)", got)
	}
	inc.RequiredKeys()[0] = "mutated"
	if inc.RequiredKeys()[0] != "tls.crt" {
		t.Error("RequiredKeys must return a copy")
	}

	exc := ExcludeKeys("tls.key")
	if exc.Exposes("tls.key") || !exc.Exposes("tls.crt") || exc.Required("tls.crt") || exc.RequiredKeys() != nil {
		t.Error("ExcludeKeys semantics wrong")
	}
}

func TestAllowsClient(t *testing.T) {
	e := Exposure{AllowedCIDRs: []netip.Prefix{
		netip.MustParsePrefix("10.10.30.40/32"),
		netip.MustParsePrefix("2001:db8::/64"),
	}}
	cases := map[string]bool{
		"10.10.30.40":        true,
		"10.10.30.41":        false,
		"::ffff:10.10.30.40": true,
		"2001:db8::1":        true,
		"2001:db8::1%eth0":   true,
		"2001:db9::1":        false,
	}
	for addr, want := range cases {
		if got := e.AllowsClient(netip.MustParseAddr(addr)); got != want {
			t.Errorf("AllowsClient(%s) = %v, want %v", addr, got, want)
		}
	}
	if (&Exposure{}).AllowsClient(netip.MustParseAddr("10.0.0.1")) {
		t.Error("an exposure without CIDRs must allow nobody")
	}
}

func TestReferencedSecretsDeduplicates(t *testing.T) {
	a := SecretRef{Namespace: "b", Name: "cert"}
	auth := SecretRef{Namespace: "a", Name: "creds"}
	refs := ReferencedSecrets([]Exposure{
		{Name: "one", Source: a, Auth: Auth{SecretRef: auth}},
		{Name: "two", Source: a, Auth: Auth{SecretRef: auth}},
		{Name: "self", Source: auth, Auth: Auth{SecretRef: auth}},
	})
	if want := []SecretRef{auth, a}; !slices.Equal(refs, want) {
		t.Fatalf("ReferencedSecrets = %v, want %v", refs, want)
	}
}

func TestParsePrefix(t *testing.T) {
	valid := []string{"10.0.0.0/8", "10.10.30.40/32", "0.0.0.0/0", "2001:db8::/32", "::/0", "2001:db8::1/128"}
	for _, s := range valid {
		if _, err := ParsePrefix(s); err != nil {
			t.Errorf("ParsePrefix(%q): %v", s, err)
		}
	}
	invalid := []string{"", "10.0.0.1", "10.0.0.1/24", "10.0.0.0/33", "::ffff:10.0.0.0/104", "2001:db8::1/64", "fe80::/64%eth0", " 10.0.0.0/8", "localhost/32"}
	for _, s := range invalid {
		if _, err := ParsePrefix(s); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", s)
		}
	}
}

func TestNameAndKeyValidation(t *testing.T) {
	for _, name := range []string{"my-cert", "matrix-prod", "a", "cert.example.com"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", "My-Cert", "my_cert", "..", ".", "a/b", "%2e", "-x", "x-"} {
		if ValidateName(name) == nil {
			t.Errorf("ValidateName(%q) accepted", name)
		}
	}
	for _, key := range []string{"tls.crt", "ca.crt", "KEY_NAME", ".dotfile", "a-b"} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q): %v", key, err)
		}
	}
	for _, key := range []string{"", ".", "..", "..x", "a/b", "a%2fb", "a b", "a\\b", "a\x00"} {
		if ValidateKey(key) == nil {
			t.Errorf("ValidateKey(%q) accepted", key)
		}
	}
	if ValidateNamespace("certificates") != nil || ValidateNamespace("a.b") == nil {
		t.Error("namespace validation wrong")
	}
}
