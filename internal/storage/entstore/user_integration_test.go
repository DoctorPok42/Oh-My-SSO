package entstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	userRepo := entstore.NewUserRepository(client)

	username := "alice-" + uuid.NewString()[:8]
	email := username + "@example.com"

	u, err := userRepo.Create(ctx, repository.CreateUserParams{
		RealmID:      realm.ID,
		Username:     username,
		Email:        email,
		PasswordHash: "argon2id$fake-hash-for-test",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == "" {
		t.Fatal("Create: expected a generated ID, got empty string")
	}
	if u.RealmID != realm.ID {
		t.Errorf("Create: RealmID = %q, want %q", u.RealmID, realm.ID)
	}

	got, err := userRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Username != username {
		t.Errorf("GetByID: Username = %q, want %q", got.Username, username)
	}

	byEmail, err := userRepo.GetByRealmAndEmail(ctx, realm.ID, email)
	if err != nil {
		t.Fatalf("GetByRealmAndEmail: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Errorf("GetByRealmAndEmail: ID = %q, want %q", byEmail.ID, u.ID)
	}

	byUsername, err := userRepo.GetByRealmAndUsername(ctx, realm.ID, username)
	if err != nil {
		t.Fatalf("GetByRealmAndUsername: %v", err)
	}
	if byUsername.ID != u.ID {
		t.Errorf("GetByRealmAndUsername: ID = %q, want %q", byUsername.ID, u.ID)
	}

	newEmail := "updated-" + email
	updated, err := userRepo.Update(ctx, u.ID, repository.UpdateUserParams{
		Email: &newEmail,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Email != newEmail {
		t.Errorf("Update: Email = %q, want %q", updated.Email, newEmail)
	}
	if updated.Username != username {
		t.Errorf("Update: Username = %q, want inchangé %q (mise à jour partielle)", updated.Username, username)
	}

	if err := userRepo.Delete(ctx, u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := userRepo.GetByID(ctx, u.ID); err == nil {
		t.Error("GetByID after Delete: attendu une erreur (not found), obtenu nil")
	}
}

// A username or an e-mail address is one account, whatever its case.
func TestUserIdentifiers_IgnoreCase(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	userRepo := entstore.NewUserRepository(client)

	id := uuid.NewString()[:8]
	username, email := "dana-"+id, "dana-"+id+"@example.com"

	u, err := userRepo.Create(ctx, repository.CreateUserParams{
		RealmID:  realm.ID,
		Username: "Dana-" + id,
		Email:    "Dana-" + id + "@Example.COM",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Username != username || u.Email != email {
		t.Errorf("Create: stored %q / %q, want %q / %q", u.Username, u.Email, username, email)
	}

	byUsername, err := userRepo.GetByRealmAndUsername(ctx, realm.ID, " DANA-"+id)
	if err != nil {
		t.Fatalf("GetByRealmAndUsername: %v", err)
	}
	if byUsername.ID != u.ID {
		t.Errorf("GetByRealmAndUsername: ID = %q, want %q", byUsername.ID, u.ID)
	}
	byEmail, err := userRepo.GetByRealmAndEmail(ctx, realm.ID, "dana-"+id+"@EXAMPLE.com")
	if err != nil {
		t.Fatalf("GetByRealmAndEmail: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Errorf("GetByRealmAndEmail: ID = %q, want %q", byEmail.ID, u.ID)
	}

	if _, err := userRepo.Create(ctx, repository.CreateUserParams{
		RealmID:  realm.ID,
		Username: "DANA-" + id,
		Email:    "other-" + id + "@example.com",
	}); err == nil {
		t.Error("Create: a username that differs only by case was accepted")
	}

	renamed := "Erin-" + id
	updated, err := userRepo.Update(ctx, u.ID, repository.UpdateUserParams{Username: &renamed})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if want := "erin-" + id; updated.Username != want {
		t.Errorf("Update: Username = %q, want %q", updated.Username, want)
	}
}
