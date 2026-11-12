package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbeURL(t *testing.T) {
	for addr, want := range map[string]string{
		":8090":             "http://127.0.0.1:8090/readyz",
		"0.0.0.0:8090":      "http://127.0.0.1:8090/readyz",
		"[::]:8090":         "http://127.0.0.1:8090/readyz",
		"172.30.10.20:8090": "http://172.30.10.20:8090/readyz",
		"127.0.0.1:8190":    "http://127.0.0.1:8190/readyz",
		"[fd00::20]:8090":   "http://[fd00::20]:8090/readyz",
		"admin.internal:80": "http://admin.internal:80/readyz",
	} {
		got, err := probeURL(addr)
		require.NoError(t, err, addr)
		require.Equal(t, want, got, addr)
	}

	_, err := probeURL("8090")
	require.Error(t, err, "a port alone is not an address")
}
