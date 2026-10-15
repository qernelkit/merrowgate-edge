package firmware

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

func testRelease(t *testing.T, image []byte) []byte {
	t.Helper()
	body, err := json.Marshal(Release{
		Model:    "zt411",
		Version:  "4.2.1",
		Size:     int64(len(image)),
		ImageSum: imageSum(image),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCheckSignedBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	image := bytes.Repeat([]byte("label printer firmware "), 64)
	body := testRelease(t, image)
	raw := Format(body, ed25519.Sign(priv, body))

	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	v := &Verifier{key: pub}
	rel, err := v.Check(m, image)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rel.Model != "zt411" || rel.Version != "4.2.1" {
		t.Errorf("release = %+v", rel)
	}

	t.Run("altered body", func(t *testing.T) {
		altered := *m
		altered.Body = bytes.Replace(m.Body, []byte("4.2.1"), []byte("4.2.9"), 1)
		if _, err := v.Check(&altered, image); !errors.Is(err, ErrSignature) {
			t.Errorf("err = %v, want ErrSignature", err)
		}
	})
	t.Run("altered image", func(t *testing.T) {
		bad := bytes.Clone(image)
		bad[10] ^= 0x20
		if _, err := v.Check(m, bad); !errors.Is(err, ErrImage) {
			t.Errorf("err = %v, want ErrImage", err)
		}
	})
}

func TestParseManifestRejectsMissingFooter(t *testing.T) {
	raw := []byte(manifestHeader + "\n{}\nsignature: AAAA\n")
	if _, err := ParseManifest(raw); !errors.Is(err, errFormat) {
		t.Errorf("err = %v, want errFormat", err)
	}
}
