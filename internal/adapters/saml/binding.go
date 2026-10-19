package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	dsig "github.com/russellhaering/goxmldsig"
)

// SAML bindings: how a SAML message travels through the browser (SAML
// Bindings, OASIS, 2005).
//
//   - HTTP-Redirect (§3.4): the XML is DEFLATE-compressed, base64 encoded and
//     put in the URL (?SAMLRequest= or ?SAMLResponse=). A signature is NOT in
//     the XML but in two more parameters, SigAlg and Signature.
//   - HTTP-POST (§3.5): the XML is base64 encoded in a form field, and its
//     signature, if any, is inside the XML (XML-DSig).

const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	paramRequest  = "SAMLRequest"
	paramResponse = "SAMLResponse"

	// Size limits: a SAML request is a few kilobytes. The limits stop a
	// "zip bomb" (a tiny DEFLATE stream that inflates to gigabytes).
	maxEncodedMessage = 64 << 10  // base64 text in a URL or a form field
	maxXMLMessage     = 256 << 10 // XML after decoding / inflating
	maxPOSTBody       = 512 << 10
	// The spec caps RelayState at 80 bytes, but common service providers
	// (SimpleSAMLphp...) put a return URL in it: accept more, echo it back
	// escaped, never interpret it.
	maxRelayState = 2048
)

var errBadMessage = errors.New("saml: malformed message")

// inbound is a SAML message received from the browser.
type inbound struct {
	Binding    string
	Param      string // SAMLRequest or SAMLResponse
	XML        []byte
	RelayState string

	// HTTP-Redirect only: SigAlg and Signature parameters, and the exact
	// octets they sign.
	SigAlg     string
	Signature  []byte
	SignedPart string
}

// readInbound reads the first of params that is present, in the binding
// the request uses (GET: Redirect, POST: POST).
func readInbound(w http.ResponseWriter, r *http.Request, params ...string) (*inbound, error) {
	switch r.Method {
	case http.MethodGet:
		return readRedirect(r.URL.RawQuery, params)
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxPOSTBody)
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("%w: form: %v", errBadMessage, err)
		}
		return readPOST(r.PostForm, params)
	default:
		return nil, fmt.Errorf("%w: method %s", errBadMessage, r.Method)
	}
}

// readRedirect parses the raw query by hand: the signature covers the
// parameters exactly as they were sent (their URL encoding included), which
// url.ParseQuery would lose (SAML Bindings §3.4.4.1).
func readRedirect(rawQuery string, params []string) (*inbound, error) {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			return nil, fmt.Errorf("%w: query", errBadMessage)
		}
		switch key {
		case paramRequest, paramResponse, "RelayState", "SigAlg", "Signature":
			if _, dup := raw[key]; dup {
				return nil, fmt.Errorf("%w: parameter %s repeated", errBadMessage, key)
			}
			raw[key] = v
		}
	}
	in := &inbound{Binding: bindingRedirect}
	for _, p := range params {
		if v, ok := raw[p]; ok {
			in.Param = p
			msg, err := url.QueryUnescape(v)
			if err != nil {
				return nil, fmt.Errorf("%w: %s encoding", errBadMessage, p)
			}
			deflated, err := decodeBase64(msg)
			if err != nil {
				return nil, err
			}
			if in.XML, err = inflate(deflated); err != nil {
				return nil, err
			}
			in.SignedPart = p + "=" + v
			break
		}
	}
	if in.Param == "" {
		return nil, fmt.Errorf("%w: no %s", errBadMessage, strings.Join(params, " or "))
	}
	if v, ok := raw["RelayState"]; ok {
		rs, err := url.QueryUnescape(v)
		if err != nil || len(rs) > maxRelayState {
			return nil, fmt.Errorf("%w: RelayState", errBadMessage)
		}
		in.RelayState = rs
		in.SignedPart += "&RelayState=" + v
	}
	sigAlg, hasAlg := raw["SigAlg"]
	sig, hasSig := raw["Signature"]
	if hasAlg != hasSig {
		return nil, fmt.Errorf("%w: SigAlg and Signature go together", errBadMessage)
	}
	if hasSig {
		alg, err := url.QueryUnescape(sigAlg)
		if err != nil {
			return nil, fmt.Errorf("%w: SigAlg", errBadMessage)
		}
		in.SigAlg = alg
		in.SignedPart += "&SigAlg=" + sigAlg
		s, err := url.QueryUnescape(sig)
		if err != nil {
			return nil, fmt.Errorf("%w: Signature", errBadMessage)
		}
		if in.Signature, err = decodeBase64(s); err != nil {
			return nil, err
		}
	} else {
		in.SignedPart = ""
	}
	return in, nil
}

func readPOST(form url.Values, params []string) (*inbound, error) {
	in := &inbound{Binding: bindingPOST}
	for _, p := range params {
		if vs := form[p]; len(vs) > 0 {
			if len(vs) > 1 {
				return nil, fmt.Errorf("%w: parameter %s repeated", errBadMessage, p)
			}
			in.Param = p
			var err error
			if in.XML, err = decodeBase64(vs[0]); err != nil {
				return nil, err
			}
			if len(in.XML) > maxXMLMessage {
				return nil, fmt.Errorf("%w: too large", errBadMessage)
			}
			break
		}
	}
	if in.Param == "" {
		return nil, fmt.Errorf("%w: no %s", errBadMessage, strings.Join(params, " or "))
	}
	if vs := form["RelayState"]; len(vs) > 0 {
		if len(vs) > 1 || len(vs[0]) > maxRelayState {
			return nil, fmt.Errorf("%w: RelayState", errBadMessage)
		}
		in.RelayState = vs[0]
	}
	return in, nil
}

func decodeBase64(s string) ([]byte, error) {
	if len(s) > maxEncodedMessage {
		return nil, fmt.Errorf("%w: too large", errBadMessage)
	}
	// Some senders wrap base64 in lines: drop the whitespace first.
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64", errBadMessage)
	}
	return b, nil
}

// inflate undoes the raw DEFLATE of the Redirect binding, with a hard cap.
func inflate(b []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	out, err := io.ReadAll(io.LimitReader(fr, maxXMLMessage+1))
	if err != nil {
		return nil, fmt.Errorf("%w: deflate", errBadMessage)
	}
	if len(out) > maxXMLMessage {
		return nil, fmt.Errorf("%w: too large", errBadMessage)
	}
	return out, nil
}

// redirectURL builds a signed HTTP-Redirect binding URL to dest.
func (k *signingKey) redirectURL(ctx context.Context, dest, param string, xmlMsg []byte, relayState string) (string, error) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(xmlMsg); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sig, err := k.signQuery(ctx, q)
	if err != nil {
		return "", err
	}
	q += "&Signature=" + url.QueryEscape(sig)
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	return dest + sep + q, nil
}
