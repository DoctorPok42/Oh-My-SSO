package geoip

import (
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Resolver reads a country database. Safe for concurrent use.
type Resolver struct {
	db *maxminddb.Reader
}

// Open loads the database at path.
func Open(path string) (*Resolver, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &Resolver{db: db}, nil
}

// Close releases the file.
func (r *Resolver) Close() error { return r.db.Close() }

// Description says which database is loaded (logs).
func (r *Resolver) Description() string {
	return fmt.Sprintf("%s, built %s", r.db.Metadata.DatabaseType, r.db.Metadata.BuildTime().UTC().Format("2006-01-02"))
}

// record is the part of a country record we read. The same layout is used
// by DB-IP and MaxMind ("country" → "iso_code", "names").
type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
}

// Country implements service.GeoIPResolver.
func (r *Resolver) Country(ip string) (code, name string, ok bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", "", false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return "", "", false
	}
	var rec record
	if err := r.db.Lookup(addr).Decode(&rec); err != nil {
		return "", "", false
	}
	code, names := rec.Country.ISOCode, rec.Country.Names
	if code == "" {
		code, names = rec.RegisteredCountry.ISOCode, rec.RegisteredCountry.Names
	}
	if code == "" {
		return "", "", false
	}
	name = names["en"]
	if name == "" {
		name = code
	}
	return code, name, true
}
