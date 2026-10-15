package firmware

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// A manifest file is a JSON body between two framing lines, then the signature
// over the body bytes:
//
//	-----BEGIN DEPOT MANIFEST-----
//	{"model":"zt411","version":"4.2.1",...}
//	-----END DEPOT MANIFEST-----
//	signature: <base64>
//
// The framing lets depot staff paste a manifest into a support ticket without the
// mail client rewrapping the body.
const manifestHeader = "-----BEGIN DEPOT MANIFEST-----"
const manifestFooter = "-----END DEPOT MANIFEST-----"
const signaturePrefix = "signature: "

// Manifest is a parsed manifest file. Body is exactly the bytes that were signed.
type Manifest struct {
	Body      []byte
	Signature []byte
}

var errFormat = errors.New("firmware: malformed manifest")

// ParseManifest splits a manifest file into its body and signature.
func ParseManifest(raw []byte) (*Manifest, error) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	rest, ok := bytes.CutPrefix(raw, []byte(manifestHeader+"\n"))
	if !ok {
		return nil, fmt.Errorf("%w: missing header line", errFormat)
	}
	body, trailer, ok := bytes.Cut(rest, []byte("\n"+manifestFooter+"\n"))
	if !ok {
		return nil, fmt.Errorf("%w: missing footer line", errFormat)
	}
	line, ok := bytes.CutPrefix(bytes.TrimSpace(trailer), []byte(signaturePrefix))
	if !ok {
		return nil, fmt.Errorf("%w: missing signature line", errFormat)
	}
	sig, err := base64.StdEncoding.DecodeString(string(line))
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", errFormat, err)
	}
	return &Manifest{Body: body, Signature: sig}, nil
}

// Format writes a manifest file; release tooling and tests use it.
func Format(body, signature []byte) []byte {
	var b bytes.Buffer
	b.WriteString(manifestHeader + "\n")
	b.Write(body)
	b.WriteString("\n" + manifestFooter + "\n")
	b.WriteString(signaturePrefix + base64.StdEncoding.EncodeToString(signature) + "\n")
	return b.Bytes()
}
