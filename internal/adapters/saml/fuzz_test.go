package saml

import (
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// The two entry points that read bytes sent by a service provider. Run for
// real with: go test -run=^$ -fuzz=FuzzParseXML -fuzztime=60s ./internal/adapters/saml
// (a plain `go test` only replays the seeds). The property is the absence of
// a panic and, when verification succeeds, the signed element of the seed:
// a mutated message that still verifies must not hand back anything else.

func fuzzSeeds(f *testing.F) (seeds [][]byte, k *spKey) {
	k = validSPKey(f, false)
	seeds = [][]byte{
		signedAuthnRequest(f, k, dsig.RSASHA256SignatureMethod, "_seed"),
		[]byte(`<a xmlns="urn:x"><b/></a>`),
		[]byte(`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>`),
		[]byte(`<a><!-- c --><b>`),
		{},
	}
	return seeds, k
}

func FuzzParseXML(f *testing.F) {
	seeds, _ := fuzzSeeds(f)
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if doc, err := parseXML(b); err == nil && doc.Root() == nil {
			t.Fatal("no error but no root")
		}
	})
}

func FuzzVerifyInbound(f *testing.F) {
	seeds, k := fuzzSeeds(f)
	for _, s := range seeds {
		f.Add(s)
	}
	a, app := testAdapter(), appWith(k)
	f.Fuzz(func(t *testing.T, b []byte) {
		doc, err := parseXML(b)
		if err != nil {
			return
		}
		el, err := a.verifyInbound(&inbound{Binding: bindingPOST, XML: b}, doc.Root(), app)
		if err == nil && el.SelectAttrValue("ID", "") != "_seed" {
			t.Fatalf("verified a message whose signed element is not the seed: %q", b)
		}
	})
}
