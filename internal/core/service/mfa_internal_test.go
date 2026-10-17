package service

// White-box tests of the pure functions behind MFA: policy resolution, TOTP
// code matching, backup code format. They need no fake at all.

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
)

func TestResolveMFARequirement(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	methods := func(m ...domain.MfaMethodType) []domain.MfaMethodType { return m }
	const (
		totp    = domain.MfaMethodTOTP
		passkey = domain.MfaMethodPasskey
		backup  = domain.MfaMethodBackupCodes
	)

	tests := []struct {
		name         string
		in           mfaPolicyInput
		wantRequired bool
		wantAllowed  []domain.MfaMethodType
		wantSources  []string
		wantDue      time.Time
		wantStepUp   bool
		wantErr      error
	}{
		{
			name: "nothing configured: optional, any method",
		},
		{
			name:         "realm requires MFA for everyone",
			in:           mfaPolicyInput{Settings: &domain.InstanceSettings{MFARequiredGlobally: true}},
			wantRequired: true, wantSources: []string{"realm"},
		},
		{
			name:         "client requires MFA",
			in:           mfaPolicyInput{Client: &domain.ClientApp{ClientID: "payroll", MFAPolicy: domain.ClientAppMFARequired}},
			wantRequired: true, wantSources: []string{"client:payroll"},
		},
		{
			name:        "client inherit with a method list: restricts methods, requires nothing",
			in:          mfaPolicyInput{Client: &domain.ClientApp{MFAPolicy: domain.ClientAppMFAInherit, MFAAllowedMethods: methods(passkey)}},
			wantAllowed: methods(passkey),
		},
		{
			name: "a client cannot relax the realm (strictest wins)",
			in: mfaPolicyInput{
				Settings: &domain.InstanceSettings{MFARequiredGlobally: true},
				Client:   &domain.ClientApp{MFAPolicy: domain.ClientAppMFAInherit},
			},
			wantRequired: true, wantSources: []string{"realm"},
		},
		{
			name: "role requires MFA, no grace",
			in: mfaPolicyInput{
				RolePolicies: []*domain.MfaPolicy{{RoleID: "r1", Required: true, RequiredSince: now.Add(-day)}},
				RoleNames:    map[string]string{"r1": "admin"},
			},
			wantRequired: true, wantSources: []string{"role:admin"},
		},
		{
			name: "role requires MFA, grace still running: not required yet, due date given",
			in: mfaPolicyInput{
				RolePolicies:  []*domain.MfaPolicy{{RoleID: "r1", Required: true, EnrollmentGraceDays: 7, RequiredSince: now.Add(-2 * day)}},
				UserCreatedAt: now.Add(-30 * day),
				Now:           now,
			},
			wantDue: now.Add(5 * day),
		},
		{
			name: "grace counts from the account creation when it is more recent",
			in: mfaPolicyInput{
				RolePolicies:  []*domain.MfaPolicy{{RoleID: "r1", Required: true, EnrollmentGraceDays: 7, RequiredSince: now.Add(-30 * day)}},
				UserCreatedAt: now.Add(-1 * day),
				Now:           now,
			},
			wantDue: now.Add(6 * day),
		},
		{
			name: "grace over: required",
			in: mfaPolicyInput{
				RolePolicies:  []*domain.MfaPolicy{{RoleID: "r1", Required: true, EnrollmentGraceDays: 7, RequiredSince: now.Add(-8 * day)}},
				RoleNames:     map[string]string{"r1": "admin"},
				UserCreatedAt: now.Add(-30 * day),
				Now:           now,
			},
			wantRequired: true, wantSources: []string{"role:admin"},
		},
		{
			name: "allowed methods intersect across sources",
			in: mfaPolicyInput{
				Client:       &domain.ClientApp{MFAPolicy: domain.ClientAppMFARequired, ClientID: "c", MFAAllowedMethods: methods(totp, passkey, backup)},
				RolePolicies: []*domain.MfaPolicy{{RoleID: "r1", AllowedMethods: methods(passkey, totp)}},
			},
			wantRequired: true, wantAllowed: methods(totp, passkey), wantSources: []string{"client:c"},
		},
		{
			name: "disjoint method lists: conflict",
			in: mfaPolicyInput{
				Client:       &domain.ClientApp{MFAAllowedMethods: methods(totp)},
				RolePolicies: []*domain.MfaPolicy{{RoleID: "r1", AllowedMethods: methods(passkey)}},
			},
			wantErr: ErrMFAPolicyConflict,
		},
		{
			name:       "step-up flag of a role is reported even if MFA is not required",
			in:         mfaPolicyInput{RolePolicies: []*domain.MfaPolicy{{RoleID: "r1", StepUpForSensitiveActions: true}}},
			wantStepUp: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.in.Now.IsZero() {
				tt.in.Now = now
			}
			got, err := resolveMFARequirement(tt.in)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantRequired, got.Required)
			require.Equal(t, tt.wantAllowed, got.AllowedMethods)
			require.Equal(t, tt.wantSources, got.Sources)
			require.Equal(t, tt.wantDue, got.EnrollmentDueAt)
			require.Equal(t, tt.wantStepUp, got.StepUpForSensitiveActions)
		})
	}
}

func TestMatchTOTP(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_800_000_015, 0) // 15 s into a 30 s window
	step := now.Unix() / totpPeriod
	code := func(counter int64) string {
		c, err := hotp.GenerateCodeCustom(secret, uint64(counter), hotp.ValidateOpts{Digits: totpDigits, Algorithm: totpAlgorithm})
		require.NoError(t, err)
		return c
	}

	got, ok := matchTOTP(secret, code(step), now)
	require.True(t, ok)
	require.Equal(t, step, got, "current window")

	got, ok = matchTOTP(secret, code(step-1), now)
	require.True(t, ok, "previous window tolerated (clock drift)")
	require.Equal(t, step-1, got)

	_, ok = matchTOTP(secret, code(step+1), now)
	require.True(t, ok, "next window tolerated (clock drift)")

	_, ok = matchTOTP(secret, code(step-2), now)
	require.False(t, ok, "a code from a minute ago is expired")

	_, ok = matchTOTP(secret, " "+code(step)[:3]+" "+code(step)[3:]+" ", now)
	require.True(t, ok, "spaces are ignored")

	for _, bad := range []string{"", "12345", "1234567", "12345a", "abcdef"} {
		_, ok = matchTOTP(secret, bad, now)
		require.False(t, ok, bad)
	}
}

func TestBackupCodeFormat(t *testing.T) {
	codes, err := generateBackupCodes()
	require.NoError(t, err)
	require.Len(t, codes, backupCodeCount)

	seen := map[string]bool{}
	for _, c := range codes {
		require.Len(t, c, backupCodeLength+1)
		require.Equal(t, byte('-'), c[5])
		norm, ok := normalizeBackupCode(c)
		require.True(t, ok)
		require.Equal(t, strings.ReplaceAll(c, "-", ""), norm)
		require.False(t, seen[norm], "codes of a batch are distinct")
		seen[norm] = true
		require.NotContains(t, norm, "I")
		require.NotContains(t, norm, "L")
		require.NotContains(t, norm, "O")
		require.NotContains(t, norm, "U")
	}

	norm, ok := normalizeBackupCode(" k7q2m 9xhrt ")
	require.True(t, ok)
	require.Equal(t, "K7Q2M9XHRT", norm, "lower case and spaces are forgiven")

	norm, ok = normalizeBackupCode("O1IL0-AAAAA")
	require.True(t, ok)
	require.Equal(t, "01110AAAAA", norm, "look-alikes O/I/L are read as 0/1/1")

	for _, bad := range []string{"", "K7Q2M", "K7Q2M-9XHRT-1", "K7Q2M-9XHRU", "K7Q2M_9XHRT"} {
		_, ok := normalizeBackupCode(bad)
		require.False(t, ok, bad)
	}

	hashes, err := hashBackupCodes(codes[:2])
	require.NoError(t, err)
	a, err := parseArgon2idHash(hashes[0])
	require.NoError(t, err)
	b, err := parseArgon2idHash(hashes[1])
	require.NoError(t, err)
	require.Equal(t, a.salt, b.salt, "one salt per batch")
	require.NotEqual(t, a.key, b.key)
	require.Equal(t, uint32(backupCodeMemory), a.memory)
	require.NotContains(t, hashes[0], strings.ReplaceAll(codes[0], "-", ""), "never stored in clear")
}
