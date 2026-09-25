package auth

import (
	"errors"
	"net/http"
	"testing"
)

func secretData(username, password string) map[string][]byte {
	return map[string][]byte{UsernameKey: []byte(username), PasswordKey: []byte(password)}
}

func request(t *testing.T, setup func(r *http.Request)) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "/exposures/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(r)
	}
	return r
}

func TestBasicVerify(t *testing.T) {
	v, err := NewBasic(secretData("fetcher", "s3cret"))
	if err != nil {
		t.Fatalf("NewBasic: %v", err)
	}
	cases := []struct {
		name  string
		setup func(r *http.Request)
		want  bool
	}{
		{"missing basic auth", nil, false},
		{"valid credentials", func(r *http.Request) { r.SetBasicAuth("fetcher", "s3cret") }, true},
		{"incorrect username", func(r *http.Request) { r.SetBasicAuth("fetcherx", "s3cret") }, false},
		{"incorrect password", func(r *http.Request) { r.SetBasicAuth("fetcher", "s3cret!") }, false},
		{"password prefix", func(r *http.Request) { r.SetBasicAuth("fetcher", "s3cre") }, false},
		{"swapped fields", func(r *http.Request) { r.SetBasicAuth("s3cret", "fetcher") }, false},
		{"empty credentials", func(r *http.Request) { r.SetBasicAuth("", "") }, false},
		{"other scheme", func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret") }, false},
		{"malformed base64", func(r *http.Request) { r.Header.Set("Authorization", "Basic !!!") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.Verify(request(t, tc.setup)); got != tc.want {
				t.Fatalf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMalformedSecret(t *testing.T) {
	cases := []struct {
		name string
		data map[string][]byte
		want error
	}{
		{"nil data", nil, ErrMissingUsername},
		{"username key missing", map[string][]byte{PasswordKey: []byte("p")}, ErrMissingUsername},
		{"password key missing", map[string][]byte{UsernameKey: []byte("u")}, ErrMissingPassword},
		{"empty username", secretData("", "p"), ErrMissingUsername},
		{"empty password", secretData("u", ""), ErrMissingPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewBasic(tc.data); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	v, _ := NewBasic(secretData("u", "p"))
	if got, want := v.Challenge(), `Basic realm="kube-secret-gateway"`; got != want {
		t.Fatalf("Challenge = %q, want %q", got, want)
	}
}

func TestCredentialsAreComparedExactly(t *testing.T) {
	v, err := NewBasic(secretData("fetcher\n", "s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verify(request(t, func(r *http.Request) { r.SetBasicAuth("fetcher", "s3cret") })) {
		t.Fatal("line endings in stored credentials were ignored")
	}
	if v.Verify(request(t, func(r *http.Request) { r.SetBasicAuth("fetcher\n", "s3cret") })) {
		t.Fatal("password line ending was ignored")
	}
	if v.Verify(request(t, func(r *http.Request) { r.SetBasicAuth("fetcher", "s3cret\n") })) {
		t.Fatal("username line ending was ignored")
	}
	if !v.Verify(request(t, func(r *http.Request) { r.SetBasicAuth("fetcher\n", "s3cret\n") })) {
		t.Fatal("exact credential bytes did not verify")
	}
}
