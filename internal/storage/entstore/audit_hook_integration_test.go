package entstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestClientAppMutation_WritesAuditLog(t *testing.T) {
	ctx := context.Background()

	setupClient := newTestClient(t)
	realm := newTestRealm(t, ctx, setupClient)

	auditedClient := newTestClient(t)
	auditedClient.Use(entstore.AuditLogHook(auditedClient))

	actor := audit.Actor{UserID: uuid.NewString(), RealmID: realm.ID}
	ctx = audit.WithActor(ctx, actor)

	clientRepo := entstore.NewClientRepository(auditedClient)
	auditRepo := entstore.NewAuditLogRepository(auditedClient)

	app, err := clientRepo.Create(ctx, repository.CreateClientAppParams{
		RealmID:  realm.ID,
		Name:     "audited-client-" + uuid.NewString()[:8],
		Protocol: domain.ClientAppProtocolOIDC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	logs, err := auditRepo.ListByResource(ctx, "ClientApp", app.ID)
	if err != nil {
		t.Fatalf("ListByResource: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("aucune entrée AuditLog trouvée après création du ClientApp — le hook n'a rien écrit")
	}
	foundCreate := false
	for _, l := range logs {
		if l.Action == "create" && l.UserID == actor.UserID && l.RealmID == realm.ID {
			foundCreate = true
		}
	}
	if !foundCreate {
		t.Errorf("aucune entrée AuditLog 'create' avec l'acteur attendu (user_id=%s, realm_id=%s) parmi %d entrée(s)", actor.UserID, realm.ID, len(logs))
	}

	newName := "renamed-" + app.Name
	if _, err := clientRepo.Update(ctx, app.ID, repository.UpdateClientAppParams{Name: &newName}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	logsAfterUpdate, err := auditRepo.ListByResource(ctx, "ClientApp", app.ID)
	if err != nil {
		t.Fatalf("ListByResource after update: %v", err)
	}
	if len(logsAfterUpdate) < 2 {
		t.Fatalf("attendu au moins 2 entrées AuditLog (create + update) pour ce ClientApp, obtenu %d", len(logsAfterUpdate))
	}
	foundUpdate := false
	for _, l := range logsAfterUpdate {
		if l.Action == "update" {
			foundUpdate = true
		}
	}
	if !foundUpdate {
		t.Error("aucune entrée AuditLog 'update' trouvée après la mutation Update")
	}
}
