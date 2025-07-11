package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"loopgate/internal/auth"
	"loopgate/internal/storage"
	"loopgate/internal/types"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// UserHandlers holds dependencies for user-specific handlers (e.g., API key management).
type UserHandlers struct {
	Storage    storage.StorageAdapter
	APIKeyPrefix string // To be passed from config, e.g., "lk_pub_"
}

// NewUserHandlers creates a new UserHandlers.
func NewUserHandlers(storage storage.StorageAdapter, apiKeyPrefix string) *UserHandlers {
	return &UserHandlers{
		Storage:    storage,
		APIKeyPrefix: apiKeyPrefix,
	}
}

// CreateAPIKeyRequest defines the expected JSON structure for creating an API key.
type CreateAPIKeyRequest struct {
	Label     string `json:"label,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"` // Expected format: RFC3339, e.g., "2024-12-31T23:59:59Z"
}

// CreateAPIKeyResponse defines the JSON structure for a successful API key creation.
type CreateAPIKeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	RawKey    string     `json:"raw_key"` // This is shown only once
	Label     string     `json:"label,omitempty"`
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// APIKeyDetailsResponse defines the JSON structure for listing API keys (omits sensitive data).
type APIKeyDetailsResponse struct {
	ID         uuid.UUID  `json:"id"`
	Label      string     `json:"label,omitempty"`
	Prefix     string     `json:"prefix"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	IsActive   bool       `json:"is_active"`
}


// CreateAPIKeyHandler handles the creation of a new API key for the authenticated user.
// POST /api/user/apikeys
func (h *UserHandlers) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, err := GetUserClaimsFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for default settings
		if err.Error() != "EOF" {
			http.Error(w, "Invalid request payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	defer r.Body.Close()

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "Invalid expires_at format. Use RFC3339 (e.g., 2024-12-31T23:59:59Z)", http.StatusBadRequest)
			return
		}
		expiresAt = &t
	}

	rawKey, keyHash, err := auth.GenerateAPIKey(h.APIKeyPrefix)
	if err != nil {
		http.Error(w, "Failed to generate API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newAPIKey := &types.APIKey{
		// ID will be generated by storage
		UserID:    userClaims.UserID,
		KeyHash:   keyHash,
		Label:     strings.TrimSpace(req.Label),
		Prefix:    h.APIKeyPrefix, // Store the prefix used
		ExpiresAt: expiresAt,
		IsActive:  true,
	}

	if err := h.Storage.CreateAPIKey(newAPIKey); err != nil {
		http.Error(w, "Failed to store API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateAPIKeyResponse{
		ID:        newAPIKey.ID,
		RawKey:    rawKey,
		Label:     newAPIKey.Label,
		Prefix:    newAPIKey.Prefix,
		ExpiresAt: newAPIKey.ExpiresAt,
		CreatedAt: newAPIKey.CreatedAt,
	})
}

// ListAPIKeysHandler lists all API keys for the authenticated user.
// GET /api/user/apikeys
func (h *UserHandlers) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, err := GetUserClaimsFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	storedKeys, err := h.Storage.GetAPIKeysByUserID(userClaims.UserID)
	if err != nil {
		http.Error(w, "Failed to retrieve API keys: "+err.Error(), http.StatusInternalServerError)
		return
	}

	responseKeys := make([]APIKeyDetailsResponse, 0, len(storedKeys))
	for _, key := range storedKeys {
		responseKeys = append(responseKeys, APIKeyDetailsResponse{
			ID:         key.ID,
			Label:      key.Label,
			Prefix:     key.Prefix,
			LastUsedAt: key.LastUsedAt,
			ExpiresAt:  key.ExpiresAt,
			CreatedAt:  key.CreatedAt,
			IsActive:   key.IsActive,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseKeys)
}

// RevokeAPIKeyHandler revokes an API key for the authenticated user.
// DELETE /api/user/apikeys/{key_id}
func (h *UserHandlers) RevokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, err := GetUserClaimsFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyIDStr, ok := vars["key_id"]
	if !ok {
		http.Error(w, "API key ID not provided in path", http.StatusBadRequest)
		return
	}

	apiKeyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		http.Error(w, "Invalid API key ID format", http.StatusBadRequest)
		return
	}

	err = h.Storage.RevokeAPIKey(apiKeyID, userClaims.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "api key not found or not owned by user") {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, "Failed to revoke API key: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "API key revoked successfully"})
}
