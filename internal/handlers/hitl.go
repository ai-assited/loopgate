package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"loopgate/internal/session"
	"loopgate/internal/telegram"
	"loopgate/internal/types"
	"loopgate/internal/whatsapp"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type HITLHandler struct {
	sessionManager *session.Manager
	telegramBot    *telegram.Bot
	whatsappBot    *whatsapp.Bot
}

func NewHITLHandler(sessionManager *session.Manager, telegramBot *telegram.Bot, whatsappBot *whatsapp.Bot) *HITLHandler {
	return &HITLHandler{
		sessionManager: sessionManager,
		telegramBot:    telegramBot,
		whatsappBot:    whatsappBot,
	}
}

func (h *HITLHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/register", h.RegisterSession).Methods("POST")
	router.HandleFunc("/request", h.SubmitRequest).Methods("POST")
	router.HandleFunc("/poll", h.PollRequest).Methods("GET")
	router.HandleFunc("/status", h.GetStatus).Methods("GET")
	router.HandleFunc("/deactivate", h.DeactivateSession).Methods("POST")
	router.HandleFunc("/pending", h.ListPendingRequests).Methods("GET")
	router.HandleFunc("/cancel", h.CancelRequest).Methods("POST")
}

func (h *HITLHandler) RegisterSession(w http.ResponseWriter, r *http.Request) {
	var req types.SessionRegistration
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.ClientID == "" {
		http.Error(w, "Missing required fields: session_id and client_id", http.StatusBadRequest)
		return
	}

	if req.TelegramID == 0 && req.WhatsappJID == "" {
		http.Error(w, "Missing required field: either telegram_id or whatsapp_jid must be provided", http.StatusBadRequest)
		return
	}

	err := h.sessionManager.RegisterSession(req.SessionID, req.ClientID, req.TelegramID, req.WhatsappJID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register session: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Registered session: %s for client: %s (TelegramID: %d, WhatsappJID: %s)", req.SessionID, req.ClientID, req.TelegramID, req.WhatsappJID)

	response := map[string]interface{}{
		"success":    true,
		"session_id": req.SessionID,
		"message":    "Session registered successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *HITLHandler) SubmitRequest(w http.ResponseWriter, r *http.Request) {
	var req types.HITLRequest
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.ClientID == "" || req.Message == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	req.ID = uuid.New().String()
	req.Status = types.RequestStatusPending
	req.CreatedAt = time.Now()
	
	if req.Timeout == 0 {
		req.Timeout = 300
	}

	if req.RequestType == "" {
		if len(req.Options) > 0 {
			req.RequestType = types.RequestTypeChoice
		} else {
			req.RequestType = types.RequestTypeInput
		}
	}

	session, err := h.sessionManager.GetSession(req.SessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Session not found: %v", err), http.StatusNotFound)
		return
	}

	if !session.Active {
		http.Error(w, "Session is not active", http.StatusBadRequest)
		return
	}

	h.sessionManager.StoreRequest(&req)

	var sendError error
	sentVia := ""

	// Determine channel preference
	// TODO: Make this logic more robust, perhaps checking session capabilities directly
	// For now, explicit preference in request, then check session fields.
	preference := req.ChannelPreference
	if preference == "" {
		preference = "any" // Default to any
	}

	if preference == "whatsapp" || (preference == "any" && session.WhatsappJID != "") {
		if h.whatsappBot != nil {
			log.Printf("Attempting to send HITL request %s via WhatsApp to JID %s", req.ID, session.WhatsappJID)
			// Ensure the whatsappBot is connected and ready if it has such a method
			// For example: if err := h.whatsappBot.EnsureConnected(); err != nil { ... }
			sendError = h.whatsappBot.SendHITLRequest(&req)
			if sendError == nil {
				sentVia = "WhatsApp"
			} else {
				log.Printf("Failed to send HITL request %s via WhatsApp: %v", req.ID, sendError)
				// If preferred was whatsapp and it failed, should we fallback or error out?
				// For now, if "any" was chosen and whatsapp failed, try telegram. If "whatsapp" was chosen and failed, error out.
				if preference == "whatsapp" {
					http.Error(w, fmt.Sprintf("Failed to send request to WhatsApp: %v", sendError), http.StatusInternalServerError)
					return
				}
			}
		} else {
			sendError = fmt.Errorf("WhatsApp bot not configured")
			log.Printf("WhatsApp bot not configured, cannot send HITL request %s", req.ID)
			if preference == "whatsapp" {
				http.Error(w, "WhatsApp integration is not configured", http.StatusInternalServerError)
				return
			}
		}
	}

	// Try Telegram if not sent via WhatsApp or if WhatsApp was preferred but failed and preference was "any"
	if sentVia == "" && (preference == "telegram" || preference == "any") {
		if h.telegramBot != nil && session.TelegramID != 0 {
			log.Printf("Attempting to send HITL request %s via Telegram to ID %d", req.ID, session.TelegramID)
			sendError = h.telegramBot.SendHITLRequest(&req)
			if sendError == nil {
				sentVia = "Telegram"
			} else {
				log.Printf("Failed to send HITL request %s via Telegram: %v", req.ID, sendError)
			}
		} else if preference == "telegram" { // Explicitly asked for telegram but not possible
			sendError = fmt.Errorf("Telegram bot not configured or user has no Telegram ID")
			log.Printf("Cannot send HITL request %s via Telegram: %v", req.ID, sendError)
		}
	}

	if sentVia == "" {
		// If neither channel worked
		log.Printf("Failed to send HITL request %s via any channel. Last error: %v", req.ID, sendError)
		http.Error(w, fmt.Sprintf("Failed to send request via any available channel: %v", sendError), http.StatusInternalServerError)
		return
	}

	log.Printf("Submitted HITL request: %s for client: %s via %s", req.ID, req.ClientID, sentVia)

	response := map[string]interface{}{
		"success":    true,
		"request_id": req.ID,
		"status":     req.Status,
		"created_at": req.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *HITLHandler) PollRequest(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		http.Error(w, "Missing request_id parameter", http.StatusBadRequest)
		return
	}

	request, err := h.sessionManager.GetRequest(requestID)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	response := types.PollResponse{
		RequestID: requestID,
		Status:    request.Status,
		Response:  request.Response,
		Approved:  request.Approved,
		Completed: request.Status == types.RequestStatusCompleted ||
		          request.Status == types.RequestStatusTimeout ||
		          request.Status == types.RequestStatusCanceled,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *HITLHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id parameter", http.StatusBadRequest)
		return
	}

	session, err := h.sessionManager.GetSession(sessionID)
	if err != nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (h *HITLHandler) DeactivateSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	err := h.sessionManager.DeactivateSession(req.SessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to deactivate session: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Deactivated session: %s", req.SessionID)

	response := map[string]interface{}{
		"success": true,
		"message": "Session deactivated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *HITLHandler) ListPendingRequests(w http.ResponseWriter, r *http.Request) {
	pending, err := h.sessionManager.GetPendingRequests()
	if err != nil {
		log.Printf("Error getting pending requests: %v", err)
		http.Error(w, "Error retrieving pending requests", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_requests": pending,
		"count":            len(pending),
	})
}

func (h *HITLHandler) CancelRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID string `json:"request_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		http.Error(w, "Missing request_id", http.StatusBadRequest)
		return
	}

	err := h.sessionManager.CancelRequest(req.RequestID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to cancel request: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Canceled request: %s", req.RequestID)

	response := map[string]interface{}{
		"success": true,
		"message": "Request canceled successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}