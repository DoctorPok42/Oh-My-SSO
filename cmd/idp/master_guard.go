package main

import (
	"fmt"
	"strings"
)


var masterReadOnlyCommands = map[string]bool{
	"keys list":         true,
	"mfa list":          true,
	"mfa policy show":   true,
	"oidc clients list": true,
	"saml clients list": true,
	"consents list":     true,
	"users status":      true,
	"settings show":     true,
	"timeouts list":     true,
}

const masterRealmName = "master"

// guardMasterRealm returns an error when args (os.Args[1:]) is a command
// that would change the master realm.
func guardMasterRealm(args []string) error {
	var path []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		path = append(path, a)
	}
	if len(path) == 0 {
		return nil // "idp" alone or "idp serve": the server
	}
	if !strings.EqualFold(realmFlag(args), masterRealmName) {
		return nil
	}
	if masterReadOnlyCommands[strings.Join(path, " ")] {
		return nil
	}
	return fmt.Errorf("the %q realm (admin console) cannot be changed with this binary: "+
		"use idp-admin on the admin network, or the admin panel", masterRealmName)
}

// realmFlag returns the value of --realm / -realm in args, "" if absent.
func realmFlag(args []string) string {
	for i, a := range args {
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "realm" {
			continue
		}
		if hasValue {
			return value
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
