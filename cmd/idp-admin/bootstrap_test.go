package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The break-glass commands refuse to run without a person at a terminal,
// and stop when the code shown is not typed back. Both checks happen before
// anything touches the database.
func TestRecover_Guardrails(t *testing.T) {
	t.Setenv("DATABASE_URL", "") // nothing below may reach the database

	var out bytes.Buffer
	code := recoverCmd([]string{"admin", "--email", "x@example.test"}, strings.NewReader("ANYTHING\n"), &out, false)
	require.Equal(t, 4, code)
	require.Contains(t, out.String(), "interactive terminal")

	out.Reset()
	code = recoverCmd([]string{"client-secret"}, strings.NewReader("WRONG1\n"), &out, true)
	require.Equal(t, 5, code)
	require.Contains(t, out.String(), "BREAK-GLASS")
	require.Contains(t, out.String(), "nothing was changed")

	out.Reset()
	require.Equal(t, 2, recoverCmd([]string{"admin"}, strings.NewReader(""), &out, true), "--email is required")
	require.Equal(t, 2, recoverCmd([]string{"everything"}, strings.NewReader(""), &out, true))
}

func TestAllowedNets(t *testing.T) {
	nets, err := allowedNets(" 10.0.0.5, 10.1.0.0/16 ,, ::1 ")
	require.NoError(t, err)
	require.Len(t, nets, 3)
	require.Equal(t, "10.0.0.5/32", nets[0].String())
	require.Equal(t, "10.1.0.0/16", nets[1].String())
	require.Equal(t, "::1/128", nets[2].String())

	nets, err = allowedNets("")
	require.NoError(t, err)
	require.Empty(t, nets)

	_, err = allowedNets("10.0.0.300")
	require.Error(t, err)
}
