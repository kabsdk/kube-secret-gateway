package gwtest

import "testing"

// canonicalBody is the exact exposure body that a gateway returns for a Secret
// holding ca.crt="CA" and tls.crt="X": keys sorted, values base64, no
// whitespace.
//
// The same literal is asserted in the server's own test suite
// (TestGETExposureCanonicalSnapshot in internal/server/server_test.go). The two repos
// share no code, so this pair of assertions is what keeps them agreed on the
// wire format: if either side ever changes the serialisation, the ETag of
// every exposure changes with it and every client re-downloads, so the change
// must be deliberate.
const canonicalBody = `{"ca.crt":"Q0E=","tls.crt":"WA=="}`

func TestCanonicalBody(t *testing.T) {
	values := map[string][]byte{"tls.crt": []byte("X"), "ca.crt": []byte("CA")}
	if got := string(body(values)); got != canonicalBody {
		t.Fatalf("body = %s\nwant    %s", got, canonicalBody)
	}
	// Map iteration order must not reach the output.
	for range 20 {
		if got := string(body(values)); got != canonicalBody {
			t.Fatalf("body is not stable: %s", got)
		}
	}
	if got := string(body(map[string][]byte{})); got != "{}" {
		t.Fatalf("empty body = %s, want {}", got)
	}
}

func TestETagDependsOnBodyAndUID(t *testing.T) {
	payload := []byte(canonicalBody)
	tag := etag(payload, "uid-a")
	if again := etag(payload, "uid-a"); again != tag {
		t.Fatal("etag is not deterministic")
	}
	if etag(payload, "uid-b") == tag {
		t.Fatal("etag does not depend on the UID")
	}
	if etag([]byte(`{"ca.crt":"Q0E="}`), "uid-a") == tag {
		t.Fatal("etag does not depend on the body")
	}
}
