package main

import (
	"bytes"
	"encoding/json"
	"log"
	"loopgate/config"
	"loopgate/internal/auth"
	"loopgate/internal/handlers"
	"loopgate/internal/storage"
	"loopgate/internal/types"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testServer *httptest.Server
var testStorageAdapter storage.StorageAdapter
var testConfig *config.Config

func setupTestEnvironment(t *testing.T, adminUser, adminPass string) func() {
	t.Helper()

	// Use a unique DB for each test run to avoid interference
	dbFile := "test_main_app_" + time.Now().Format("20060102150405.000000") + ".db"
	testDSN := "file:" + dbFile + "?cache=shared" // Using file-based SQLite for some persistence checks

	originalStorageAdapterEnv := os.Getenv("STORAGE_ADAPTER")
	originalPostgresDSNEnv := os.Getenv("POSTGRES_DSN")
	originalSQLiteDSNEnv := os.Getenv("SQLITE_DSN")
	originalJWTSecretEnv := os.Getenv("JWT_SECRET_KEY")
	originalAdminUserEnv := os.Getenv("INITIAL_ADMIN_USER")
	originalAdminPassEnv := os.Getenv("INITIAL_ADMIN_PASSWORD")

	os.Setenv("STORAGE_ADAPTER", "sqlite")
	os.Setenv("SQLITE_DSN", testDSN)
	os.Setenv("JWT_SECRET_KEY", "test-secret-for-main-test")
	if adminUser != "" {
		os.Setenv("INITIAL_ADMIN_USER", adminUser)
	} else {
		os.Unsetenv("INITIAL_ADMIN_USER")
	}
	if adminPass != "" {
		os.Setenv("INITIAL_ADMIN_PASSWORD", adminPass)
	} else {
		os.Unsetenv("INITIAL_ADMIN_PASSWORD")
	}

	testConfig = config.Load()

	// Initialize storage directly for verification purposes
	var err error
	sqliteAdapter, err := storage.NewSQLiteStorageAdapter(testConfig.SQLiteDSN)
	require.NoError(t, err)
	testStorageAdapter = sqliteAdapter

	// Run the main function's core logic in a controlled way
	// This simulates what main() does but allows us to inject test configurations
	// and control the server lifecycle.
	// We don't call main() directly because it logs fatal on errors and starts its own listener.

	// Setup initial admin user (mimicking the logic in main.go)
	if testConfig.InitialAdminUser != "" && testConfig.InitialAdminPassword != "" {
		_, err := testStorageAdapter.GetUserByUsername(testConfig.InitialAdminUser)
		if err != nil {
			if strings.Contains(err.Error(), "user not found") {
				hashedPassword, hashErr := auth.HashPassword(testConfig.InitialAdminPassword)
				require.NoError(t, hashErr)
				adminUserToCreate := &types.User{
					Username:     testConfig.InitialAdminUser,
					PasswordHash: hashedPassword,
					IsAdmin:      true,
				}
				createErr := testStorageAdapter.CreateUser(adminUserToCreate)
				require.NoError(t, createErr)
				log.Printf("Test: Initial admin user '%s' created.", testConfig.InitialAdminUser)
			} else {
				require.NoError(t, err, "Failed to check for initial admin user during test setup")
			}
		} else {
			log.Printf("Test: Initial admin user '%s' already exists.", testConfig.InitialAdminUser)
		}
	}

	// Setup router and server (similar to main.go but using httptest)
	// MCP Server and HITL Handler are nil for these auth-focused tests
	// Telegram bot is also not needed here.
	r := router.NewRouter(nil, nil, testStorageAdapter, testConfig)
	testServer = httptest.NewServer(r)

	return func() {
		testServer.Close()
		if saCloser, ok := testStorageAdapter.(interface{ Close() error }); ok {
			saCloser.Close()
		}
		os.Remove(dbFile) // Clean up the test database file

		// Restore original environment variables
		os.Setenv("STORAGE_ADAPTER", originalStorageAdapterEnv)
		os.Setenv("POSTGRES_DSN", originalPostgresDSNEnv)
		os.Setenv("SQLITE_DSN", originalSQLiteDSNEnv)
		os.Setenv("JWT_SECRET_KEY", originalJWTSecretEnv)
		os.Setenv("INITIAL_ADMIN_USER", originalAdminUserEnv)
		os.Setenv("INITIAL_ADMIN_PASSWORD", originalAdminPassEnv)
		if originalStorageAdapterEnv == "" { os.Unsetenv("STORAGE_ADAPTER") }
		if originalPostgresDSNEnv == "" { os.Unsetenv("POSTGRES_DSN") }
		if originalSQLiteDSNEnv == "" { os.Unsetenv("SQLITE_DSN") }
		if originalJWTSecretEnv == "" { os.Unsetenv("JWT_SECRET_KEY") }
		if originalAdminUserEnv == "" { os.Unsetenv("INITIAL_ADMIN_USER") }
		if originalAdminPassEnv == "" { os.Unsetenv("INITIAL_ADMIN_PASSWORD") }
	}
}

func TestInitialAdminUserCreation(t *testing.T) {
	adminUsername := "initadmin"
	adminPassword := "initpass123"

	cleanup := setupTestEnvironment(t, adminUsername, adminPassword)
	defer cleanup()

	// Verify admin user was created by setup logic (which mimics main.go)
	adminUser, err := testStorageAdapter.GetUserByUsername(adminUsername)
	require.NoError(t, err, "Admin user should have been created by startup logic")
	require.NotNil(t, adminUser)
	assert.True(t, adminUser.IsAdmin, "Initial user should be an admin")
	assert.Equal(t, adminUsername, adminUser.Username)

	// Attempt to "restart" server (re-run setup logic for admin creation)
	// This is simulated by directly calling the admin creation part of setup again.
	// The setupTestEnvironment already contains the logic to create the admin if it doesn't exist.
	// So, if we call it again, it should find the existing admin and not try to recreate or error.

	// To be more explicit, let's simulate the check from main.go again
	_, err = testStorageAdapter.GetUserByUsername(testConfig.InitialAdminUser)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			// This block should not be reached if the admin was created initially
			t.Fatalf("Admin user %s was not found on second check, but should exist.", testConfig.InitialAdminUser)
		} else {
			t.Fatalf("Error checking for admin user on second pass: %v", err)
		}
	}
	// If we reach here without error, it means the user exists, which is the expected behavior.
	log.Printf("Test: Second check for admin user '%s' found existing user, as expected.", testConfig.InitialAdminUser)
}

func TestInitialAdminUser_NotCreatedIfNoConfig(t *testing.T) {
	cleanup := setupTestEnvironment(t, "", "") // No admin user/pass configured
	defer cleanup()

	// Check if any users exist (should be none if admin wasn't configured)
	// This is a simplification; a more robust check would be to list all users
	// or check for a specific admin username if one was accidentally created.
	// For now, we assume no other users are created by default.
	_, err := testStorageAdapter.GetUserByUsername("anyadmin") // Try a generic name
	assert.Error(t, err, "No admin user should be created if not configured")
	if err != nil {
		assert.Contains(t, err.Error(), "user not found")
	}
}


func TestRegularUserRegistration_IsAdminFalse(t *testing.T) {
	cleanup := setupTestEnvironment(t, "tempadmin", "temppass") // Admin setup to ensure server runs
	defer cleanup()

	regUsername := "testuser"
	regPassword := "testpass123"

	payload := handlers.RegisterUserRequest{
		Username: regUsername,
		Password: regPassword,
	}
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/register", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "User registration should succeed")

	var regResp map[string]string
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)
	assert.NotEmpty(t, regResp["user_id"], "Response should contain user_id")

	// Verify in storage
	registeredUser, err := testStorageAdapter.GetUserByUsername(regUsername)
	require.NoError(t, err, "Registered user should be found in storage")
	require.NotNil(t, registeredUser)
	assert.False(t, registeredUser.IsAdmin, "Newly registered user should not be an admin")
	assert.Equal(t, regUsername, registeredUser.Username)

	userID, uuidErr := uuid.Parse(regResp["user_id"])
	require.NoError(t, uuidErr)
	assert.Equal(t, userID, registeredUser.ID)
}

func TestLoginHandler(t *testing.T) {
	adminUsername := "loginadmin"
	adminPassword := "loginpass123"
	cleanup := setupTestEnvironment(t, adminUsername, adminPassword)
	defer cleanup()

	// First, ensure the admin user (created by setup) can log in
	loginPayload := handlers.LoginUserRequest{
		Username: adminUsername,
		Password: adminPassword,
	}
	payloadBytes, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest("POST", testServer.URL+"/api/auth/login", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Admin login should succeed")

	var loginResp handlers.LoginUserResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp.Token, "Login response should contain a token")
	assert.Equal(t, adminUsername, loginResp.Username)

	adminUser, _ := testStorageAdapter.GetUserByUsername(adminUsername)
	assert.Equal(t, adminUser.ID, loginResp.UserID)

	// Test login with incorrect password
	loginPayload.Password = "wrongpassword"
	payloadBytes, _ = json.Marshal(loginPayload)
	req, _ = http.NewRequest("POST", testServer.URL+"/api/auth/login", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Login with incorrect password should fail")

	// Test login with non-existent user
	loginPayload.Username = "nonexistentuser"
	payloadBytes, _ = json.Marshal(loginPayload)
	req, _ = http.NewRequest("POST", testServer.URL+"/api/auth/login", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Login with non-existent user should fail")
}

func TestUserAPIKeyRoutes_WithJWTAuth(t *testing.T) {
	adminUsername := "jwtuser"
	adminPassword := "jwtpass123"
	cleanup := setupTestEnvironment(t, adminUsername, adminPassword)
	defer cleanup()

	// 1. Login to get a token
	loginPayload := handlers.LoginUserRequest{
		Username: adminUsername,
		Password: adminPassword,
	}
	loginPayloadBytes, _ := json.Marshal(loginPayload)
	loginReq, _ := http.NewRequest("POST", testServer.URL+"/api/auth/login", bytes.NewBuffer(loginPayloadBytes))
	loginReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	loginResp, err := client.Do(loginReq)
	require.NoError(t, err)
	defer loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var lr handlers.LoginUserResponse
	err = json.NewDecoder(loginResp.Body).Decode(&lr)
	require.NoError(t, err)
	require.NotEmpty(t, lr.Token)

	// 2. Test POST /api/user/apikeys (Create API Key)
	createAPIKeyPayload := handlers.CreateAPIKeyRequest{Label: "test-key-for-jwt-user"}
	createAPIKeyBytes, _ := json.Marshal(createAPIKeyPayload)
	apiKeyReq, _ := http.NewRequest("POST", testServer.URL+"/api/user/apikeys", bytes.NewBuffer(createAPIKeyBytes))
	apiKeyReq.Header.Set("Content-Type", "application/json")
	apiKeyReq.Header.Set("Authorization", "Bearer "+lr.Token)

	apiKeyResp, err := client.Do(apiKeyReq)
	require.NoError(t, err)
	defer apiKeyResp.Body.Close()

	assert.Equal(t, http.StatusCreated, apiKeyResp.StatusCode, "Create API key should succeed with valid JWT")

	var createResp handlers.CreateAPIKeyResponse
	err = json.NewDecoder(apiKeyResp.Body).Decode(&createResp)
	require.NoError(t, err)
	assert.NotEmpty(t, createResp.RawKey)
	assert.Equal(t, "test-key-for-jwt-user", createResp.Label)

	// 3. Test GET /api/user/apikeys (List API Keys)
	listAPIKeysReq, _ := http.NewRequest("GET", testServer.URL+"/api/user/apikeys", nil)
	listAPIKeysReq.Header.Set("Authorization", "Bearer "+lr.Token)
	listAPIKeysResp, err := client.Do(listAPIKeysReq)
	require.NoError(t, err)
	defer listAPIKeysResp.Body.Close()
	assert.Equal(t, http.StatusOK, listAPIKeysResp.StatusCode, "List API keys should succeed with valid JWT")
	var listResp []handlers.APIKeyDetailsResponse
	err = json.NewDecoder(listAPIKeysResp.Body).Decode(&listResp)
	require.NoError(t, err)
	assert.Len(t, listResp, 1)
	assert.Equal(t, createResp.ID, listResp[0].ID)


	// 4. Test POST /api/user/apikeys without token
	apiKeyReqNoAuth, _ := http.NewRequest("POST", testServer.URL+"/api/user/apikeys", bytes.NewBuffer(createAPIKeyBytes))
	apiKeyReqNoAuth.Header.Set("Content-Type", "application/json")
	apiKeyRespNoAuth, err := client.Do(apiKeyReqNoAuth)
	require.NoError(t, err)
	defer apiKeyRespNoAuth.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, apiKeyRespNoAuth.StatusCode, "Create API key should fail without JWT")

	// 5. Test POST /api/user/apikeys with invalid token
	apiKeyReqInvalidAuth, _ := http.NewRequest("POST", testServer.URL+"/api/user/apikeys", bytes.NewBuffer(createAPIKeyBytes))
	apiKeyReqInvalidAuth.Header.Set("Content-Type", "application/json")
	apiKeyReqInvalidAuth.Header.Set("Authorization", "Bearer invalidtoken")
	apiKeyRespInvalidAuth, err := client.Do(apiKeyReqInvalidAuth)
	require.NoError(t, err)
	defer apiKeyRespInvalidAuth.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, apiKeyRespInvalidAuth.StatusCode, "Create API key should fail with invalid JWT")
}

// TODO: Add more tests:
// - Test registration with existing username
// - Test registration with invalid payload (e.g., missing username/password, short password)
// - If JWTAuthMiddleware is testable here, test authenticated endpoints.
// - Test the logic for different storage backends if that's easy to switch in test setup.
//   (Currently hardcoded to sqlite for simplicity in test setup).
// - Test the main.go startup more directly if possible, rather than mimicking its setup.
//   This might require refactoring main.go to be more testable (e.g., separating server setup and start).
// - Test API key creation/listing/revoking once user auth is solid. (Partially done with TestUserAPIKeyRoutes_WithJWTAuth)
// - Test User Handlers require authentication. (Partially done)

func TestHITLRegisterRoute_WithAPIKeyAuth(t *testing.T) {
	// No initial admin needed for this test, we'll create users/keys manually
	cleanup := setupTestEnvironment(t, "", "")
	defer cleanup()

	// 1. Create a user directly in storage to own the API key
	testUser := &types.User{
		Username:     "apikeyowner",
		PasswordHash: "somehash", // Not used for API key auth directly
		IsAdmin:      false,
	}
	err := testStorageAdapter.CreateUser(testUser)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, testUser.ID)

	// 2. Create an API key for this user directly in storage
	rawKey, hashedKey, err := auth.GenerateAPIKey(testConfig.APIKeyPrefix)
	require.NoError(t, err)
	apiKey := &types.APIKey{
		UserID:    testUser.ID,
		KeyHash:   hashedKey,
		Label:     "hitl-test-key",
		Prefix:    testConfig.APIKeyPrefix,
		IsActive:  true,
		CreatedAt: time.Now(),
	}
	err = testStorageAdapter.CreateAPIKey(apiKey)
	require.NoError(t, err)

	// 3. Prepare HITL registration payload
	hitlRegPayload := types.SessionRegistration{
		SessionID:  "hitl-test-session-1",
		ClientID:   "hitl-test-client-1",
		TelegramID: 1234567890,
	}
	hitlRegBytes, _ := json.Marshal(hitlRegPayload)

	client := &http.Client{}

	// 4. Test /hitl/register without API key
	hitlReqNoAuth, _ := http.NewRequest("POST", testServer.URL+"/hitl/register", bytes.NewBuffer(hitlRegBytes))
	hitlReqNoAuth.Header.Set("Content-Type", "application/json")
	hitlRespNoAuth, err := client.Do(hitlReqNoAuth)
	require.NoError(t, err)
	defer hitlRespNoAuth.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, hitlRespNoAuth.StatusCode, "HITL register should fail without API key")

	// 5. Test /hitl/register with invalid API key
	hitlReqInvalidAuth, _ := http.NewRequest("POST", testServer.URL+"/hitl/register", bytes.NewBuffer(hitlRegBytes))
	hitlReqInvalidAuth.Header.Set("Content-Type", "application/json")
	hitlReqInvalidAuth.Header.Set("Authorization", "Bearer invalidapikey123")
	hitlRespInvalidAuth, err := client.Do(hitlReqInvalidAuth)
	require.NoError(t, err)
	defer hitlRespInvalidAuth.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, hitlRespInvalidAuth.StatusCode, "HITL register should fail with invalid API key")

	// 6. Test /hitl/register with valid API key (using Authorization: Bearer method)
	hitlReqValidAuthBearer, _ := http.NewRequest("POST", testServer.URL+"/hitl/register", bytes.NewBuffer(hitlRegBytes))
	hitlReqValidAuthBearer.Header.Set("Content-Type", "application/json")
	hitlReqValidAuthBearer.Header.Set("Authorization", "Bearer "+rawKey)
	hitlRespValidAuthBearer, err := client.Do(hitlReqValidAuthBearer)
	require.NoError(t, err)
	defer hitlRespValidAuthBearer.Body.Close()
	assert.Equal(t, http.StatusOK, hitlRespValidAuthBearer.StatusCode, "HITL register should succeed with valid API key via Bearer token")
	var hitlRegResp map[string]interface{}
	err = json.NewDecoder(hitlRespValidAuthBearer.Body).Decode(&hitlRegResp)
	require.NoError(t, err)
	assert.True(t, hitlRegResp["success"].(bool))
	assert.Equal(t, hitlRegPayload.SessionID, hitlRegResp["session_id"])


	// 7. Test /hitl/register with valid API key (using X-API-Key method)
		// First, deactivate the previous session to avoid "session already registered" if DB is not perfectly clean between sub-tests
	_, err = testStorageAdapter.GetSession(hitlRegPayload.SessionID)
	if err == nil { // if session exists
		err = testStorageAdapter.DeactivateSession(hitlRegPayload.SessionID)
		require.NoError(t, err)
	}
	// Use a slightly different session ID to ensure it's a new registration
	hitlRegPayload.SessionID = "hitl-test-session-2"
	hitlRegBytesXKey, _ := json.Marshal(hitlRegPayload)

	hitlReqValidAuthXKey, _ := http.NewRequest("POST", testServer.URL+"/hitl/register", bytes.NewBuffer(hitlRegBytesXKey))
	hitlReqValidAuthXKey.Header.Set("Content-Type", "application/json")
	hitlReqValidAuthXKey.Header.Set("X-API-Key", rawKey)
	hitlRespValidAuthXKey, err := client.Do(hitlReqValidAuthXKey)
	require.NoError(t, err)
	defer hitlRespValidAuthXKey.Body.Close()
	assert.Equal(t, http.StatusOK, hitlRespValidAuthXKey.StatusCode, "HITL register should succeed with valid API key via X-API-Key header")
	var hitlRegRespXKey map[string]interface{}
	err = json.NewDecoder(hitlRespValidAuthXKey.Body).Decode(&hitlRegRespXKey)
	require.NoError(t, err)
	assert.True(t, hitlRegRespXKey["success"].(bool))
	assert.Equal(t, hitlRegPayload.SessionID, hitlRegRespXKey["session_id"])
}

// Note: The current setupTestEnvironment mimics parts of main.go's initialization.
// A more robust approach for full integration testing of main.go would be to
// refactor main.go so that server setup and start can be invoked programmatically
// without os.Exit or log.Fatal calls that would terminate the test.
// For instance, main() could call a run() function that returns an error.
// The current approach is a pragmatic way to test the interaction of components.
