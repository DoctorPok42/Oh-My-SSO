package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/memstore"
)

// realmsByID is the one method of RealmRepository that the policy service uses.
type realmsByID struct {
	repository.RealmRepository
	byID  map[string]*domain.Realm
	reads int
}

func (r *realmsByID) GetByID(_ context.Context, id string) (*domain.Realm, error) {
	r.reads++
	return r.byID[id], nil
}

// In master, a list of methods without passkey or security key is refused when
// it is set (it would fail every sign-in with a conflict), and the realm is
// read once, not at each check.
func TestMFAPolicy_MasterMethods(t *testing.T) {
	const masterID, otherID = "realm-master", "realm-other"
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	realms := &realmsByID{byID: map[string]*domain.Realm{
		masterID: {ID: masterID, Name: service.MasterRealmName, IsSystemRealm: true},
		otherID:  {ID: otherID, Name: "demo"},
	}}
	clients := &mfaClientRepo{byID: map[string]*domain.ClientApp{
		"c-master": {ID: "c-master", RealmID: masterID, ClientID: "c-master-id"},
		"c-other":  {ID: "c-other", RealmID: otherID, ClientID: "c-other-id"},
	}}
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Realms:   realms,
		Settings: &mfaSettingsRepo{byRelm: map[string]*domain.InstanceSettings{}},
		Clients:  clients,
		Roles: &mfaRoleRepo{roles: []*domain.Role{
			{ID: "r-master", RealmID: masterID, Name: "ops"}, {ID: "r-other", RealmID: otherID, Name: "ops"}}},
		Policies: memstore.NewMfaPolicies(clock),
		Now:      clock,
	})
	ctx := context.Background()
	totp, passkey := []domain.MfaMethodType{domain.MfaMethodTOTP}, []domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodPasskey}

	_, err := policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: masterID, ClientRef: "c-master", Policy: domain.ClientAppMFARequired, AllowedMethods: totp})
	require.ErrorIs(t, err, service.ErrInvalidMFAPolicy)
	_, err = policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: masterID, RoleName: "ops", AllowedMethods: totp})
	require.ErrorIs(t, err, service.ErrInvalidMFAPolicy)

	_, err = policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: masterID, ClientRef: "c-master", Policy: domain.ClientAppMFARequired, AllowedMethods: passkey})
	require.NoError(t, err, "a list with a passkey is fine")
	_, err = policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: masterID, ClientRef: "c-master", Policy: domain.ClientAppMFAInherit})
	require.NoError(t, err, "no list: any method, master narrows it itself")
	_, err = policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: otherID, ClientRef: "c-other", Policy: domain.ClientAppMFARequired, AllowedMethods: totp})
	require.NoError(t, err, "other realms take TOTP only")

	before := realms.reads
	user := &domain.User{ID: "u", RealmID: masterID}
	for range 3 {
		req, err := policy.Requirement(ctx, user, nil)
		require.NoError(t, err)
		require.True(t, req.Required)
	}
	require.Zero(t, realms.reads-before, "the realm is known by now: no read per check")
}
