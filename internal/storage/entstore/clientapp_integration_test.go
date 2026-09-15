package entstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestClientAppCRUD(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	clientRepo := entstore.NewClientRepository(client)

	name := "test-client-" + uuid.NewString()[:8]

	// --- Create ---
	app, err := clientRepo.Create(ctx, repository.CreateClientAppParams{
		RealmID:  realm.ID,
		Name:     name,
		Protocol: domain.ClientAppProtocolOIDC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if app.ID == "" {
		t.Fatal("Create: expected a generated ID, got empty string")
	}
	if app.Status != domain.ClientAppActive {
		t.Errorf("Create: Status = %q, want default %q", app.Status, domain.ClientAppActive)
	}
	if app.Protocol != domain.ClientAppProtocolOIDC {
		t.Errorf("Create: Protocol = %q, want %q", app.Protocol, domain.ClientAppProtocolOIDC)
	}

	// --- GetByID ---
	got, err := clientRepo.GetByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name != name {
		t.Errorf("GetByID: Name = %q, want %q", got.Name, name)
	}

	// --- Update ---
	newName := "renamed-" + name
	clientID := "abc123"
	updated, err := clientRepo.Update(ctx, app.ID, repository.UpdateClientAppParams{
		Name:     &newName,
		ClientID: &clientID,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("Update: Name = %q, want %q", updated.Name, newName)
	}
	if updated.ClientID != clientID {
		t.Errorf("Update: ClientID = %q, want %q", updated.ClientID, clientID)
	}

	// --- GetByRealmAndClientID ---
	byClientID, err := clientRepo.GetByRealmAndClientID(ctx, realm.ID, clientID)
	if err != nil {
		t.Fatalf("GetByRealmAndClientID: %v", err)
	}
	if byClientID.ID != app.ID {
		t.Errorf("GetByRealmAndClientID: ID = %q, want %q", byClientID.ID, app.ID)
	}

	// --- ListByRealm ---
	list, err := clientRepo.ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListByRealm: got %d client(s), want 1", len(list))
	}

	// --- Delete ---
	if err := clientRepo.Delete(ctx, app.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	afterDelete, err := clientRepo.GetByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetByID after soft delete: %v", err)
	}
	if !afterDelete.IsDeleted() {
		t.Error("GetByID after Delete: attendu IsDeleted() == true (soft delete)")
	}
}
