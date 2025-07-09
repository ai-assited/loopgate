package storage

import (
	"errors"
	"loopgate/internal/types"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InMemoryStorageAdapter implements the StorageAdapter interface for in-memory storage.
type InMemoryStorageAdapter struct {
	sessions         map[string]*types.Session
	requests         map[string]*types.HITLRequest
	users               map[string]*types.User // username -> user
	usersByID           map[uuid.UUID]*types.User
	apiKeys             map[string]*types.APIKey // key hash -> key
	clientToTelegramID  map[string]int64
	clientToWhatsappJID map[string]string
	mu                  sync.RWMutex
}

// NewInMemoryStorageAdapter creates a new InMemoryStorageAdapter.
func NewInMemoryStorageAdapter() *InMemoryStorageAdapter {
	return &InMemoryStorageAdapter{
		sessions:            make(map[string]*types.Session),
		requests:            make(map[string]*types.HITLRequest),
		users:               make(map[string]*types.User),
		usersByID:           make(map[uuid.UUID]*types.User),
		apiKeys:             make(map[string]*types.APIKey),
		clientToTelegramID:  make(map[string]int64),
		clientToWhatsappJID: make(map[string]string),
	}
}

// RegisterSession stores a new session.
func (s *InMemoryStorageAdapter) RegisterSession(sessionID, clientID string, telegramID int64, whatsappJID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[sessionID]; exists {
		return errors.New("session already exists")
	}

	session := &types.Session{
		ID:          sessionID,
		ClientID:    clientID,
		TelegramID:  telegramID,
		WhatsappJID: whatsappJID,
		Active:      true,
		CreatedAt:   time.Now(),
	}

	s.sessions[sessionID] = session
	if telegramID != 0 {
		s.clientToTelegramID[clientID] = telegramID
	}
	if whatsappJID != "" {
		s.clientToWhatsappJID[clientID] = whatsappJID
	}
	// log.Printf("InmemoryStore: Registered session %s for client %s with Telegram ID %d and WhatsApp JID %s", sessionID, clientID, telegramID, whatsappJID)
	return nil
}

// DeactivateSession marks a session as inactive.
func (s *InMemoryStorageAdapter) DeactivateSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	session.Active = false
	// Consider if ClientID should be removed or session just marked inactive
	// For now, we remove them to prevent sending messages to deactivated sessions.
	if session.TelegramID != 0 {
		delete(s.clientToTelegramID, session.ClientID)
	}
	if session.WhatsappJID != "" {
		delete(s.clientToWhatsappJID, session.ClientID)
	}
	return nil
}

// GetSession retrieves a session by its ID.
func (s *InMemoryStorageAdapter) GetSession(sessionID string) (*types.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}
	return session, nil
}

// GetTelegramID retrieves the Telegram ID associated with a Client ID.
func (s *InMemoryStorageAdapter) GetTelegramID(clientID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	telegramID, exists := s.clientToTelegramID[clientID]
	if !exists {
		// Try to find an active session with this clientID and get its TelegramID
		for _, session := range s.sessions {
			if session.ClientID == clientID && session.Active && session.TelegramID != 0 {
				return session.TelegramID, nil
			}
		}
		return 0, errors.New("client not found or no active telegram session")
	}
	return telegramID, nil
}

// GetWhatsappJID retrieves the WhatsApp JID associated with a Client ID.
func (s *InMemoryStorageAdapter) GetWhatsappJID(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	whatsappJID, exists := s.clientToWhatsappJID[clientID]
	if !exists {
		// Try to find an active session with this clientID and get its WhatsappJID
		for _, session := range s.sessions {
			if session.ClientID == clientID && session.Active && session.WhatsappJID != "" {
				return session.WhatsappJID, nil
			}
		}
		return "", errors.New("client not found or no active whatsapp session")
	}
	return whatsappJID, nil
}

// StoreRequest stores a new HITL request.
func (s *InMemoryStorageAdapter) StoreRequest(request *types.HITLRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[request.ID]; exists {
		return errors.New("request already exists")
	}
	s.requests[request.ID] = request
	return nil
}

// GetRequest retrieves a HITL request by its ID.
func (s *InMemoryStorageAdapter) GetRequest(requestID string) (*types.HITLRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, exists := s.requests[requestID]
	if !exists {
		return nil, errors.New("request not found")
	}
	return request, nil
}

// GetRequestByWhatsappMsgID retrieves a HITL request by its WhatsApp message ID.
func (s *InMemoryStorageAdapter) GetRequestByWhatsappMsgID(whatsappMsgID string) (*types.HITLRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, request := range s.requests {
		if request.WhatsappMsgID == whatsappMsgID {
			return request, nil
		}
	}
	return nil, errors.New("request not found for whatsapp message id")
}

// UpdateRequestResponse updates the response and status of a HITL request.
func (s *InMemoryStorageAdapter) UpdateRequestResponse(requestID, response string, approved bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, exists := s.requests[requestID]
	if !exists {
		return errors.New("request not found")
	}

	now := time.Now()
	request.Response = response
	request.Approved = approved
	request.Status = types.RequestStatusCompleted
	request.RespondedAt = &now
	return nil
}

// GetPendingRequests retrieves all requests with a 'pending' status.
func (s *InMemoryStorageAdapter) GetPendingRequests() ([]*types.HITLRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var pending []*types.HITLRequest
	for _, request := range s.requests {
		if request.Status == types.RequestStatusPending {
			pending = append(pending, request)
		}
	}
	return pending, nil
}

// CancelRequest marks a request as 'canceled'.
func (s *InMemoryStorageAdapter) CancelRequest(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, exists := s.requests[requestID]
	if !exists {
		return errors.New("request not found")
	}
	request.Status = types.RequestStatusCanceled
	return nil
}

// GetActiveSessions retrieves all sessions that are currently active.
func (s *InMemoryStorageAdapter) GetActiveSessions() ([]*types.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*types.Session
	for _, session := range s.sessions {
		if session.Active {
			active = append(active, session)
		}
	}
	return active, nil
}

// --- User management methods ---

func (s *InMemoryStorageAdapter) CreateUser(user *types.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.Username]; exists {
		return errors.New("user already exists")
	}
	s.users[user.Username] = user
	s.usersByID[user.ID] = user
	return nil
}

func (s *InMemoryStorageAdapter) GetUserByUsername(username string) (*types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *InMemoryStorageAdapter) GetUserByID(userID uuid.UUID) (*types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.usersByID[userID]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// --- APIKey management methods ---

func (s *InMemoryStorageAdapter) CreateAPIKey(apiKey *types.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.apiKeys[apiKey.KeyHash]; exists {
		return errors.New("API key already exists")
	}
	s.apiKeys[apiKey.KeyHash] = apiKey
	return nil
}

func (s *InMemoryStorageAdapter) GetAPIKeyByHash(keyHash string) (*types.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	apiKey, exists := s.apiKeys[keyHash]
	if !exists {
		return nil, errors.New("api key not found")
	}
	return apiKey, nil
}

func (s *InMemoryStorageAdapter) GetActiveAPIKeyByHash(keyHash string) (*types.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	apiKey, exists := s.apiKeys[keyHash]
	if !exists || !apiKey.IsActive {
		return nil, errors.New("active api key not found")
	}
	return apiKey, nil
}

func (s *InMemoryStorageAdapter) GetAPIKeysByUserID(userID uuid.UUID) ([]*types.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var userKeys []*types.APIKey
	for _, apiKey := range s.apiKeys {
		if apiKey.UserID == userID {
			userKeys = append(userKeys, apiKey)
		}
	}
	return userKeys, nil
}

func (s *InMemoryStorageAdapter) RevokeAPIKey(apiKeyID uuid.UUID, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, apiKey := range s.apiKeys {
		if apiKey.ID == apiKeyID && apiKey.UserID == userID {
			apiKey.IsActive = false
			return nil
		}
	}
	return errors.New("api key not found or not owned by user")
}

func (s *InMemoryStorageAdapter) UpdateAPIKeyLastUsed(apiKeyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, apiKey := range s.apiKeys {
		if apiKey.ID == apiKeyID {
			now := time.Now()
			apiKey.LastUsedAt = &now
			return nil
		}
	}
	return errors.New("api key not found")
}
