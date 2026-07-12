package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

func TestManager_MarkResult_XAIPermissionDeniedAutoDisablesAuth(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	store := &captureTokenStore{}
	m := NewManager(store, nil, nil)
	m.SetConfig(&internalconfig.Config{
		XAI: internalconfig.XAIConfig{AutoDisableOnPermissionDenied: true},
	})

	auth := &Auth{
		ID:       "xai-alice@example.com.json",
		Provider: "xai",
		FileName: "xai-alice@example.com.json",
		Metadata: map[string]any{"type": "xai"},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "grok-4.5"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "xai", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "xai",
		Model:    model,
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusForbidden,
			Code:       "permission-denied",
			Message:    `{"code":"permission-denied","error":"Access to the chat endpoint is denied."}`,
		},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth present")
	}
	if !updated.Disabled || updated.Status != StatusDisabled {
		t.Fatalf("disabled/status = %v/%s, want disabled", updated.Disabled, updated.Status)
	}
	if got, _ := updated.Metadata["disabled"].(bool); !got {
		t.Fatalf("metadata.disabled = %#v, want true", updated.Metadata["disabled"])
	}
	if got := updated.Metadata["disabled_reason"]; got != "xai_permission_denied" {
		t.Fatalf("disabled_reason = %#v, want xai_permission_denied", got)
	}
	if store.saves == 0 {
		t.Fatalf("expected auth to be persisted after auto-disable")
	}
	if count := reg.GetModelCount(model); count != 0 {
		t.Fatalf("model count = %d after permanent disable, want 0", count)
	}
}

func TestManager_MarkResult_XAIPermissionDeniedRespectsConfigOff(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{
		XAI: internalconfig.XAIConfig{AutoDisableOnPermissionDenied: false},
	})

	auth := &Auth{
		ID:       "xai-bob@example.com.json",
		Provider: "xai",
		FileName: "xai-bob@example.com.json",
		Metadata: map[string]any{"type": "xai"},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "grok-4.5-config-off"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "xai", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "xai",
		Model:    model,
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusForbidden,
			Code:       "permission-denied",
			Message:    "Access to the chat endpoint is denied.",
		},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth present")
	}
	if updated.Disabled || updated.Status == StatusDisabled {
		t.Fatalf("auth should not be permanently disabled when config is off")
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state")
	}
	if state.NextRetryAfter.IsZero() {
		t.Fatalf("expected temporary cooldown when config is off")
	}
	if diff := time.Until(state.NextRetryAfter); diff < 25*time.Minute || diff > 35*time.Minute {
		t.Fatalf("cooldown = %v, want ~30m", diff)
	}
}

func TestManager_MarkResult_XAIPaymentRequiredDoesNotAutoDisable(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{
		XAI: internalconfig.XAIConfig{AutoDisableOnPermissionDenied: true},
	})

	auth := &Auth{
		ID:       "xai-carol@example.com.json",
		Provider: "xai",
		FileName: "xai-carol@example.com.json",
		Metadata: map[string]any{"type": "xai"},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "grok-4.5-payment"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "xai", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "xai",
		Model:    model,
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusPaymentRequired,
			Code:       "personal-team-blocked:spending-limit",
			Message:    "You have run out of credits",
		},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth present")
	}
	if updated.Disabled || updated.Status == StatusDisabled {
		t.Fatalf("402 spending-limit must not permanently disable auth")
	}
}

func TestManager_MarkResult_NonXAIPermissionDeniedDoesNotAutoDisable(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{
		XAI: internalconfig.XAIConfig{AutoDisableOnPermissionDenied: true},
	})

	auth := &Auth{
		ID:       "claude-user.json",
		Provider: "claude",
		FileName: "claude-user.json",
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "claude-sonnet"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "claude",
		Model:    model,
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusForbidden,
			Code:       "permission-denied",
			Message:    "permission-denied",
		},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth present")
	}
	if updated.Disabled || updated.Status == StatusDisabled {
		t.Fatalf("non-xai auth must not be auto-disabled")
	}
}

type captureTokenStore struct {
	saves int
}

func (s *captureTokenStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *captureTokenStore) Save(_ context.Context, auth *Auth) (string, error) {
	if s != nil {
		s.saves++
	}
	if auth == nil {
		return "", nil
	}
	return auth.ID, nil
}
func (s *captureTokenStore) Delete(context.Context, string) error { return nil }
