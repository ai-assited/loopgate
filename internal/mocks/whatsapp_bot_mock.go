package mocks

import (
	"loopgate/internal/types"
	"github.com/stretchr/testify/mock"
)

type MockWhatsappBot struct {
	mock.Mock
}

func (m *MockWhatsappBot) SendHITLRequest(request *types.HITLRequest) error {
	args := m.Called(request)
	// Simulate updating WhatsappMsgID, if no error
	if args.Error(0) == nil && request != nil {
		request.WhatsappMsgID = "whatsapp-mock-id"
	}
	return args.Error(0)
}

func (m *MockWhatsappBot) Start() {
	// Mock Start method
}

func (m *MockWhatsappBot) Stop() {
	// Mock Stop method
}

func (m *MockWhatsappBot) Connect() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockWhatsappBot) EnsureConnected() error {
	args := m.Called()
	return args.Error(0)
}

// Add other methods that might be called by the handler if any
