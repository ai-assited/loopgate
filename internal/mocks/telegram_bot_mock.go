package mocks

import (
	"loopgate/internal/types"
	"github.com/stretchr/testify/mock"
)

type MockTelegramBot struct {
	mock.Mock
}

func (m *MockTelegramBot) SendHITLRequest(request *types.HITLRequest) error {
	args := m.Called(request)
	// Update TelegramMsgID as the real bot does, if no error
	if args.Error(0) == nil && request != nil {
		request.TelegramMsgID = 12345 // Mocked message ID
	}
	return args.Error(0)
}

func (m *MockTelegramBot) Start() {
	// Mock Start method
}

// Add other methods that might be called by the handler if any
// For example, if the handler needed to check bot status or something.
// For current HITLHandler, only SendHITLRequest and Start (implicitly by main) are relevant.
// However, HITLHandler itself doesn't call Start.
