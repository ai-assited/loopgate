package handlers_test

import (
	"bytes"
	"encoding/json"
	"loopgate/internal/handlers"
	"loopgate/internal/mocks"
	"loopgate/internal/session"
	"loopgate/internal/storage"
	"loopgate/internal/types"
	"net/http"
	"net/http/httptest"
	"testing"
	"errors"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHITLHandler_RegisterSession(t *testing.T) {
	mockStorage := storage.NewInMemoryStorageAdapter()
	sessionManager := session.NewManager(mockStorage)

	// Bots can be nil for RegisterSession tests as they are not used by this handler method
	hitlHandler := handlers.NewHITLHandler(sessionManager, nil, nil)

	router := mux.NewRouter()
	hitlHandler.RegisterRoutes(router)

	testCases := []struct {
		name           string
		payload        types.SessionRegistration
		expectedStatus int
		expectedBody   string // Substring to check in response body for success/error
	}{
		{
			name: "Valid Telegram Session",
			payload: types.SessionRegistration{
				SessionID:  "sess_telegram_123",
				ClientID:   "client_telegram_abc",
				TelegramID: 1234567890,
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Session registered successfully",
		},
		{
			name: "Valid WhatsApp Session",
			payload: types.SessionRegistration{
				SessionID:   "sess_whatsapp_123",
				ClientID:    "client_whatsapp_abc",
				WhatsappJID: "1234567890@s.whatsapp.net",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Session registered successfully",
		},
		{
			name: "Valid Session with Both Telegram and WhatsApp",
			payload: types.SessionRegistration{
				SessionID:   "sess_both_123",
				ClientID:    "client_both_abc",
				TelegramID:  1234567890,
				WhatsappJID: "1234567890@s.whatsapp.net",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Session registered successfully",
		},
		{
			name: "Missing SessionID",
			payload: types.SessionRegistration{
				ClientID:   "client_no_sessid",
				TelegramID: 1234567890,
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required fields: session_id and client_id",
		},
		{
			name: "Missing ClientID",
			payload: types.SessionRegistration{
				SessionID:  "sess_no_clientid",
				TelegramID: 1234567890,
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required fields: session_id and client_id",
		},
		{
			name: "Missing Both TelegramID and WhatsappJID",
			payload: types.SessionRegistration{
				SessionID: "sess_no_contact",
				ClientID:  "client_no_contact",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required field: either telegram_id or whatsapp_jid must be provided",
		},
		{
			name:           "Invalid JSON payload",
			payload:        types.SessionRegistration{}, // Will be overridden by sending raw string
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid request body", // This is the actual error message for json.Decode error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte
			var err error

			if tc.name == "Invalid JSON payload" {
				reqBody = []byte(`{"session_id": "malformed_json",`) // Intentionally malformed
			} else {
				reqBody, err = json.Marshal(tc.payload)
				assert.NoError(t, err)
			}

			req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}

			// Verify session was actually stored for successful cases
			if tc.expectedStatus == http.StatusOK {
				storedSession, err := mockStorage.GetSession(tc.payload.SessionID)
				assert.NoError(t, err)
				assert.NotNil(t, storedSession)
				assert.Equal(t, tc.payload.ClientID, storedSession.ClientID)
				if tc.payload.TelegramID != 0 {
					assert.Equal(t, tc.payload.TelegramID, storedSession.TelegramID)
				}
				if tc.payload.WhatsappJID != "" {
					assert.Equal(t, tc.payload.WhatsappJID, storedSession.WhatsappJID)
				}
			}
		})
	}
}

// TODO: Add tests for SubmitRequest
func TestHITLHandler_SubmitRequest(t *testing.T) {
	mockStorage := storage.NewInMemoryStorageAdapter()
	sessionManager := session.NewManager(mockStorage)

	mockTelegramBot := new(mocks.MockTelegramBot)
	mockWhatsappBot := new(mocks.MockWhatsappBot)

	hitlHandler := handlers.NewHITLHandler(sessionManager, mockTelegramBot, mockWhatsappBot)

	router := mux.NewRouter()
	hitlHandler.RegisterRoutes(router)

	// Pre-register a session for testing SubmitRequest
	telegramSession := types.SessionRegistration{SessionID: "sess_tg_submit", ClientID: "client_tg_submit", TelegramID: 111}
	whatsappSession := types.SessionRegistration{SessionID: "sess_wa_submit", ClientID: "client_wa_submit", WhatsappJID: "wa_jid_111@s.whatsapp.net"}
	bothSession := types.SessionRegistration{SessionID: "sess_both_submit", ClientID: "client_both_submit", TelegramID: 222, WhatsappJID: "wa_jid_222@s.whatsapp.net"}
	noChannelSession := types.SessionRegistration{SessionID: "sess_none_submit", ClientID: "client_none_submit"} // Will be invalid but used to get session

	_ = sessionManager.RegisterSession(telegramSession.SessionID, telegramSession.ClientID, telegramSession.TelegramID, telegramSession.WhatsappJID)
	_ = sessionManager.RegisterSession(whatsappSession.SessionID, whatsappSession.ClientID, whatsappSession.TelegramID, whatsappSession.WhatsappJID)
	_ = sessionManager.RegisterSession(bothSession.SessionID, bothSession.ClientID, bothSession.TelegramID, bothSession.WhatsappJID)
	// noChannelSession is not registered with a communication ID on purpose for one test case,
	// but we need a shell session for the handler to find it.
	_ = mockStorage.RegisterSession(noChannelSession.SessionID, noChannelSession.ClientID, 0, "")


	testCases := []struct {
		name              string
		payload           types.HITLRequest
		mockTelegramSetup func()
		mockWhatsappSetup func()
		expectedStatus    int
		expectedBody      string
		expectTelegramCall bool
		expectWhatsappCall bool
	}{
		{
			name: "Send to Telegram - Preference Telegram",
			payload: types.HITLRequest{
				SessionID:         telegramSession.SessionID,
				ClientID:          telegramSession.ClientID,
				Message:           "Test Telegram",
				ChannelPreference: "telegram",
			},
			mockTelegramSetup: func() {
				mockTelegramBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(nil).Once()
			},
			mockWhatsappSetup: func() {}, // No call expected
			expectedStatus:    http.StatusOK,
			expectedBody:      "request_id",
			expectTelegramCall: true,
			expectWhatsappCall: false,
		},
		{
			name: "Send to WhatsApp - Preference WhatsApp",
			payload: types.HITLRequest{
				SessionID:         whatsappSession.SessionID,
				ClientID:          whatsappSession.ClientID,
				Message:           "Test WhatsApp",
				ChannelPreference: "whatsapp",
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {
				mockWhatsappBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(nil).Once()
			},
			expectedStatus:    http.StatusOK,
			expectedBody:      "request_id",
			expectTelegramCall: false,
			expectWhatsappCall: true,
		},
		{
			name: "Send to WhatsApp - Preference Any, WhatsApp Available",
			payload: types.HITLRequest{
				SessionID:         bothSession.SessionID, // Has both JID and TG ID
				ClientID:          bothSession.ClientID,
				Message:           "Test Any (WhatsApp first)",
				ChannelPreference: "any",
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {
				mockWhatsappBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(nil).Once()
			},
			expectedStatus:    http.StatusOK,
			expectedBody:      "request_id",
			expectTelegramCall: false,
			expectWhatsappCall: true,
		},
		{
			name: "Send to Telegram - Preference Any, WhatsApp Fails, Telegram Available",
			payload: types.HITLRequest{
				SessionID:         bothSession.SessionID,
				ClientID:          bothSession.ClientID,
				Message:           "Test Any (WhatsApp fails, Telegram fallback)",
				ChannelPreference: "any",
			},
			mockTelegramSetup: func() {
				mockTelegramBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(nil).Once()
			},
			mockWhatsappSetup: func() {
				mockWhatsappBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(errors.New("whatsapp unavailable")).Once()
			},
			expectedStatus:    http.StatusOK,
			expectedBody:      "request_id",
			expectTelegramCall: true, // Fallback
			expectWhatsappCall: true, // Attempted
		},
		{
			name: "Send to Telegram - Preference Any, Only Telegram Available",
			payload: types.HITLRequest{
				SessionID:         telegramSession.SessionID, // Only TG ID
				ClientID:          telegramSession.ClientID,
				Message:           "Test Any (Only Telegram)",
				ChannelPreference: "any",
			},
			mockTelegramSetup: func() {
				mockTelegramBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(nil).Once()
			},
			mockWhatsappSetup: func() {},
			expectedStatus:    http.StatusOK,
			expectedBody:      "request_id",
			expectTelegramCall: true,
			expectWhatsappCall: false,
		},
		{
			name: "Fail - Preference WhatsApp, WhatsApp Bot Fails",
			payload: types.HITLRequest{
				SessionID:         whatsappSession.SessionID,
				ClientID:          whatsappSession.ClientID,
				Message:           "Test WhatsApp Fail",
				ChannelPreference: "whatsapp",
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {
				mockWhatsappBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(errors.New("simulated whatsapp error")).Once()
			},
			expectedStatus:    http.StatusInternalServerError,
			expectedBody:      "Failed to send request to WhatsApp",
			expectTelegramCall: false,
			expectWhatsappCall: true,
		},
		{
			name: "Fail - Preference Telegram, Telegram Bot Fails",
			payload: types.HITLRequest{
				SessionID:         telegramSession.SessionID,
				ClientID:          telegramSession.ClientID,
				Message:           "Test Telegram Fail",
				ChannelPreference: "telegram",
			},
			mockTelegramSetup: func() {
				mockTelegramBot.On("SendHITLRequest", mock.AnythingOfType("*types.HITLRequest")).Return(errors.New("simulated telegram error")).Once()
			},
			mockWhatsappSetup: func() {},
			expectedStatus:    http.StatusInternalServerError, // This should be the behavior from the handler
			expectedBody:      "Failed to send request via any available channel", // Actual error if TG is the only option and fails
			expectTelegramCall: true,
			expectWhatsappCall: false,
		},
		{
			name: "Fail - No Channel Available in Session (Preference Any)",
			payload: types.HITLRequest{
				SessionID:         noChannelSession.SessionID, // Session has no TG ID or WA JID
				ClientID:          noChannelSession.ClientID,
				Message:           "Test No Channel",
				ChannelPreference: "any",
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {},
			expectedStatus:    http.StatusInternalServerError,
			expectedBody:      "Failed to send request via any available channel",
			expectTelegramCall: false,
			expectWhatsappCall: false,
		},
		{
			name: "Fail - Session Not Found",
			payload: types.HITLRequest{
				SessionID: "non_existent_session",
				ClientID:  "some_client",
				Message:   "Test Session Not Found",
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {},
			expectedStatus:    http.StatusNotFound,
			expectedBody:      "Session not found",
			expectTelegramCall: false,
			expectWhatsappCall: false,
		},
		{
			name: "Fail - Missing Required Fields (Message)",
			payload: types.HITLRequest{
				SessionID: telegramSession.SessionID,
				ClientID:  telegramSession.ClientID,
				// Message is missing
			},
			mockTelegramSetup: func() {},
			mockWhatsappSetup: func() {},
			expectedStatus:    http.StatusBadRequest,
			expectedBody:      "Missing required fields",
			expectTelegramCall: false,
			expectWhatsappCall: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks for each test case
			mockTelegramBot.ExpectedCalls = nil
			mockWhatsappBot.ExpectedCalls = nil
			tc.mockTelegramSetup()
			tc.mockWhatsappSetup()

			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req, err := http.NewRequest("POST", "/request", bytes.NewBuffer(payloadBytes))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code, "Status code mismatch. Body: %s", rr.Body.String())
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}

			if tc.expectTelegramCall {
				mockTelegramBot.AssertCalled(t, "SendHITLRequest", mock.AnythingOfType("*types.HITLRequest"))
			} else {
				mockTelegramBot.AssertNotCalled(t, "SendHITLRequest", mock.AnythingOfType("*types.HITLRequest"))
			}

			if tc.expectWhatsappCall {
				mockWhatsappBot.AssertCalled(t, "SendHITLRequest", mock.AnythingOfType("*types.HITLRequest"))
			} else {
				mockWhatsappBot.AssertNotCalled(t, "SendHITLRequest", mock.AnythingOfType("*types.HITLRequest"))
			}
			mockTelegramBot.AssertExpectations(t)
			mockWhatsappBot.AssertExpectations(t)
		})
	}
}
