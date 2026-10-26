package domain

const (
	// NameIDFormatPersistent: a stable, opaque identifier (the core's
	// Subject: User.ID or a pairwise value). The default.
	NameIDFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// NameIDFormatTransient: a random value, the same for the whole IdP
	// session, different at the next login.
	NameIDFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	// NameIDFormatEmail: the user's e-mail address.
	NameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// NameIDFormatUnspecified: "whatever the IdP uses"; we send the
	// persistent value.
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// NameIDFormats lists the formats this IdP can produce.
var NameIDFormats = []string{NameIDFormatPersistent, NameIDFormatTransient, NameIDFormatEmail, NameIDFormatUnspecified}
