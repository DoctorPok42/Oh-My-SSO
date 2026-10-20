// Package geoip finds the country of an IP address in a local MaxMind DB
// file (.mmdb), for the "new country" signal of the sign-in analysis (Step 12).
//
// Nothing is sent to an online service: the database is a file on disk,
// read with github.com/oschwald/maxminddb-golang. Two free country databases
// use this format:
//
//   - DB-IP "IP to Country Lite" (CC BY 4.0, no account needed):
//     https://db-ip.com/db/download/ip-to-country-lite
//   - MaxMind GeoLite2 Country (free account and licence key):
//     https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
//
// Both are updated monthly; refresh the file now and then (a cron job).
// Set GEOIP_DB_PATH to the .mmdb file; without it the signal is off.
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
