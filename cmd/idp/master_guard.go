package main

import (
	"fmt"
	"strings"
)

// Step 14 guardrail: this binary is the PUBLIC server (edge network, next to
// the end users). It may read the "master" realm (the realm of the admin
// console) but never change it: resetting the MFA of an admin, rotating the
// secret of the admin console, changing the master realm's settings... are
// only possible with cmd/idp-admin, which runs on the restricted admin
// network, and through the Admin API (RBAC, step-up MFA, audit log).
//
// An attacker who gets a shell on the public server must not be able to
// turn it into "become admin of the IdP" with one command.

// masterReadOnlyCommands may target the master realm: they change nothing.
var masterReadOnlyCommands = map[string]bool{
	"keys list":         true,
	"mfa list":          true,
	"mfa policy show":   true,
	"oidc clients list": true,
	"saml clients list": true,
	"consents list":     true,
	"users status":      true,
	"settings show":     true,
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
