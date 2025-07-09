package whatsapp

import (
	"context"
	"fmt"
	"log"
	"loopgate/internal/session"
	"loopgate/internal/types"
	"strings"

	_ "github.com/mattn/go-sqlite3" // Required for whatsmeow SQLite store
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"github.com/skip2/go-qrcode" // For QR code generation to terminal
	"os"                         // For qrterminal output

	waProto "go.mau.fi/whatsmeow/binary/proto"
	waTypes "go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

type Bot struct {
	client         *whatsmeow.Client
	sessionManager *session.Manager
	eventHandlerID uint32
	dbPath         string
	logLevel       string
}

func NewBot(sessionManager *session.Manager, dbPath string, logLevel string) (*Bot, error) {
	if dbPath == "" {
		dbPath = "whatsapp_store.db" // Default path
	}
	if logLevel == "" {
		logLevel = "INFO" // Default log level
	}

	dbLogger := waLog.Stdout("Database", logLevel, true)
	clientLogger := waLog.Stdout("Client", logLevel, true)

	dsn := dbPath
	if !strings.HasPrefix(dbPath, "file:") {
		dsn = fmt.Sprintf("file:%s?_foreign_keys=on", dbPath)
	}

	container, err := sqlstore.New("sqlite3", dsn, dbLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create whatsapp sql store at %s: %w", dbPath, err)
	}

	deviceStore, err := container.GetFirstDevice()
	if err != nil {
		log.Printf("Failed to get first WhatsApp device from store (%s), creating new one. Pairing will be required. Error: %v", dbPath, err)
		deviceStore = container.NewDevice()
		if deviceStore == nil {
			return nil, fmt.Errorf("failed to create new device store after failing to get first device")
		}
	}

	client := whatsmeow.NewClient(deviceStore, clientLogger)

	return &Bot{
		client:         client,
		dbPath:         dbPath,
		logLevel:       logLevel,
		sessionManager: sessionManager,
	}, nil
}

func (b *Bot) Start() {
	log.Println("Starting WhatsApp bot...")
	b.eventHandlerID = b.client.AddEventHandler(b.eventHandler)

	// Connect() will handle initial connection and QR code generation if needed.
	// It's designed to be non-blocking for the Start() sequence.
	if err := b.Connect(); err != nil {
		// Log non-fatal error, as Connect() might be waiting for QR scan.
		// Fatal errors during connect (like store issues) are handled in NewBot or Connect itself.
		log.Printf("WhatsApp Bot: Initial connection attempt returned: %v. Bot will try to operate once paired/connected.", err)
	}
	// Note: The bot is "started" in the sense that its event handler is registered.
	// Actual functionality depends on successful connection and pairing.
	log.Println("WhatsApp bot event handler registered. Waiting for connection and pairing if necessary.")
}


func (b *Bot) Connect() error {
	if b.client.IsConnected() && b.client.IsLoggedIn() {
		log.Println("WhatsApp client already connected and logged in.")
		return nil
	}

	if !b.client.IsConnected() {
		log.Println("WhatsApp client not connected. Attempting to connect...")
		if err := b.client.Connect(); err != nil {
			return fmt.Errorf("failed to connect whatsapp client: %w", err)
		}
		log.Println("WhatsApp client connected.")
	}


	if !b.client.IsLoggedIn() {
		log.Println("WhatsApp client connected but not logged in. Attempting to pair via QR code.")
		// No session or device means we need to pair.
		qrChan, err := b.client.GetQRChannel(context.Background())
		if err != nil {
			// This error means the client is already connected or connecting.
			// If it's already connected but not logged in, this is the state we are in.
			// if !errors.Is(err, whatsmeow.ErrQRStoreContainsID) {
			// For whatsmeow, GetQRChannel typically doesn't error if store has ID,
			// it just means we should have been logged in or restore would work.
			// The check b.client.Store.ID == nil is more direct for "new device"
			log.Printf("Error getting QR channel: %v. This might happen if already attempting to log in.", err)
            // We might still need to call Connect() again if GetQRChannel was called before initial Connect().
            // However, our current flow calls Connect() first, then checks IsLoggedIn().
		}

		// Required to make GetQRChannel work if called before the *first* Connect()
		// or if a previous Connect() attempt failed before login.
		// If already connected (but not logged in), this should re-trigger the necessary internal state.
		log.Println("Re-triggering connect for QR channel processing...")
		if err := b.client.Connect(); err != nil { // This connect is crucial for QR channel
			return fmt.Errorf("failed to connect for QR: %w", err)
		}

		log.Println("WhatsApp QR channel obtained. Waiting for QR code or login events...")
		go b.handleQR(qrChan)
		return nil // Return nil to indicate QR process started, not an immediate error
	}

	log.Println("WhatsApp client is connected and logged in.")
	return nil
}


func (b *Bot) Stop() {
	log.Println("Stopping WhatsApp bot...")
	b.client.Disconnect()
	b.client.RemoveEventHandler(b.eventHandlerID)
}

func (b *Bot) eventHandler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		b.handleMessage(v)
	case *events.Receipt:
		// Handle receipts (delivered, read) if necessary
		log.Printf("Received receipt: %+v", v)
	case *events.Connected:
		log.Println("WhatsApp client reconnected")
	case *events.Disconnected:
		log.Println("WhatsApp client disconnected")
		// Potentially handle reconnection logic here
	case *events.PairSuccess:
		log.Printf("Paired with %s, saving info", v.ID)
	case *events.LoginSuccess:
		log.Printf("Logged in to WhatsApp: %s", v.JID)
	default:
		log.Printf("Received unhandled WhatsApp event: %+v", evt)

	}
}

func (b *Bot) handleMessage(msg *events.Message) {
	// TODO: Implement message handling logic
	// This will involve:
	// 1. Identifying if the message is a reply to a HITL request.
	// 2. Extracting the response from the message.
	// 3. Updating the session manager with the response.
	// 4. Potentially handling commands similar to the Telegram bot.

	senderJID := msg.Info.Sender
	var responseText string
	var quotedMsgID string // Stanza ID of the message this one is replying to

	if convo := msg.Message.GetConversation(); convo != "" {
		responseText = convo
	} else if extText := msg.Message.GetExtendedTextMessage(); extText != nil {
		responseText = extText.GetText()
		if ctxInfo := extText.GetContextInfo(); ctxInfo != nil {
			quotedMsgID = ctxInfo.GetStanzaID()
		}
	} else {
		log.Printf("Received WhatsApp message from %s of unknown type or empty content", senderJID.String())
		return
	}

	log.Printf("Received WhatsApp message from %s: \"%s\" (QuotedMsgID: %s)", senderJID.String(), responseText, quotedMsgID)

	if quotedMsgID != "" {
		// This is likely a reply to a HITL request
		originalRequest, err := b.sessionManager.GetRequestByWhatsappMsgID(quotedMsgID)
		if err != nil {
			log.Printf("Failed to get original request for WhatsApp Msg ID %s (replied to by %s): %v", quotedMsgID, senderJID.String(), err)
			// Optionally, send a message back to user? "Sorry, I couldn't find the original request for your reply."
			return
		}

		if originalRequest.Status == types.RequestStatusCompleted || originalRequest.Status == types.RequestStatusCanceled || originalRequest.Status == types.RequestStatusTimeout {
			log.Printf("Original request %s (WhatsApp Msg ID %s) already completed/canceled/timed out. Ignoring reply from %s.", originalRequest.ID, quotedMsgID, senderJID.String())
			// Optionally, inform the user their response is too late.
			// b.SendTextMessage(senderJID.String(), "Your response for request "+originalRequest.ID+" was received, but the request is already closed.")
			return
		}

		// For now, assume any text reply is an 'approved' response.
		// More sophisticated logic could parse for keywords like "approve", "reject", or handle options if buttons weren't used.
		approved := true
		err = b.sessionManager.UpdateRequestResponse(originalRequest.ID, responseText, approved)
		if err != nil {
			log.Printf("Failed to update request %s with response from WhatsApp user %s: %v", originalRequest.ID, senderJID.String(), err)
			b.SendTextMessage(senderJID.String(), fmt.Sprintf("Error processing your response for request %s. Please try again or contact support.", originalRequest.ID))
			return
		}

		log.Printf("Successfully processed reply from %s for HITL request %s (Original WhatsApp Msg ID: %s). Response: \"%s\"", senderJID.String(), originalRequest.ID, quotedMsgID, responseText)
		// Send confirmation back to WhatsApp user
		b.SendTextMessage(senderJID.String(), fmt.Sprintf("✅ Your response for request %s (\"%s\") has been recorded.", originalRequest.ID, responseText))

	} else {
		// TODO: Handle non-reply messages (e.g., commands like /status, /start if desired)
		// For now, just log them.
		log.Printf("Received non-reply WhatsApp message from %s: \"%s\"", senderJID.String(), responseText)
		// Example: b.SendTextMessage(senderJID.String(), "I can only process replies to specific requests right now.")
	}
}

func (b *Bot) SendHITLRequest(request *types.HITLRequest) error {
	// TODO: Get WhatsApp JID (phone number) for the clientID
	if !b.client.IsConnected() || !b.client.IsLoggedIn() {
		return fmt.Errorf("WhatsApp client not connected or not logged in. Cannot send message for request ID %s", request.ID)
	}

	whatsappJIDStr, err := b.sessionManager.GetWhatsappJID(request.ClientID)
	if err != nil {
		return fmt.Errorf("failed to get whatsapp JID for client %s for request %s: %w", request.ClientID, request.ID, err)
	}
	if whatsappJIDStr == "" {
		return fmt.Errorf("no whatsapp JID found for client %s for request %s", request.ClientID, request.ID)
	}

	parsedJID, ok := waTypes.ParseJID(whatsappJIDStr)
	if !ok {
		return fmt.Errorf("failed to parse JID '%s' for request %s", whatsappJIDStr, request.ID)
	}

	var content string
	// TODO: Implement actual button messages later. For now, text representation.
	if len(request.Options) > 0 {
		content = b.createTextWithButtons(request) // This still returns a string
	} else {
		content = b.createSimpleText(request)
	}

	msg := &waProto.Message{Conversation: proto.String(content)}

	// Generate a unique message ID for context, some libraries/APIs expect this
	// For whatsmeow, it generates its own ID, but we can create one for our tracking if needed.
	// msgId := whatsmeow.GenerateMessageID()

	resp, err := b.client.SendMessage(context.Background(), parsedJID, msg)
	if err != nil {
		return fmt.Errorf("failed to send whatsapp message for request %s to %s: %w", request.ID, parsedJID.String(), err)
	}

	request.WhatsappMsgID = resp.ID // Store the actual message ID from WhatsApp
	log.Printf("Sent HITL request %s to WhatsApp JID %s. Message ID: %s", request.ID, parsedJID.String(), resp.ID)

	return nil
}


func (b *Bot) createTextWithButtons(request *types.HITLRequest) string {
	// WhatsApp Business API supports interactive messages with buttons.
	// whatsmeow might require specific formatting or use of protobuf messages for this.
	// This is a simplified text representation.
	// Actual implementation will need to construct the appropriate whatsmeow message type.
	text := fmt.Sprintf("🤖 *HITL Request*\n\n%s\n\n*Request ID:* %s\n*Client:* %s\n*Session:* %s\n\n*Options:*\n",
		request.Message, request.ID, request.ClientID, request.SessionID)
	for i, option := range request.Options {
		text += fmt.Sprintf("%d. %s\n", i+1, option)
	}
	text += "\nPlease reply with the number of your choice or your response."
	return text
}

func (b *Bot) createSimpleText(request *types.HITLRequest) string {
	text := fmt.Sprintf("🤖 *HITL Request*\n\n%s\n\n*Request ID:* %s\n*Client:* %s\n*Session:* %s\n\nPlease reply with your response.",
		request.Message, request.ID, request.ClientID, request.SessionID)
	return text
}

// TODO: Add functions to handle commands, replies, and callback queries (if applicable to WhatsApp)
// similar to the Telegram bot. WhatsApp interactions might differ, e.g. callbacks might not be
// directly transferable. Replies to specific messages will be key.

// Placeholder for getting user JID, this needs proper implementation
// func (b *Bot) getJIDForClient(clientID string) (types.JID, error) {
//    // Logic to retrieve WhatsApp JID based on clientID
//    // This might involve looking up the session or a user store.
//    return types.JID{}, fmt.Errorf("JID lookup not implemented")
// }

// Helper to send a simple text message
func (b *Bot) SendTextMessage(recipientJIDStr string, text string) error {
	// parsedJID, ok := whatsmeow.ParseJID(recipientJIDStr)
	// if !ok {
	// 	return fmt.Errorf("invalid JID: %s", recipientJIDStr)
	// }
	// msg := &waProto.Message{Conversation: proto.String(text)}
	// _, err := b.client.SendMessage(context.Background(), parsedJID, msg)
	// return err
	log.Printf("Attempting to send text message to %s: %s", recipientJIDStr, text)
	log.Println("Actual message sending is commented out pending JID and message type implementation.")
	return nil
}

// Example of how QR codes could be handled (needs to be integrated into Start())
func (b *Bot) handleQR(qrChan <-chan whatsmeow.QRChannelItem) {
	for evt := range qrChan {
		if evt.Event == "code" {
			// Render the QR code here.
			// e.g. qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
			// or just print the code: fmt.Println("QR code:", evt.Code)
			log.Printf("WhatsApp QR code: %s. Scan with WhatsApp.", evt.Code)
		} else if evt.Event == "success" {
			log.Println("WhatsApp successfully paired!")
			// Save device info here if needed, though store does it automatically
		} else if evt.Event == "timeout" {
			log.Println("WhatsApp pairing timeout, trying again...")
			// Potentially re-trigger QR generation or connect
		} else {
			log.Printf("WhatsApp login event: %s", evt.Event)
		}
	}
}

func (b *Bot) Connect() error {
	if b.client.IsConnected() {
		return nil
	}
	if err := b.client.Connect(); err != nil {
		return fmt.Errorf("failed to connect whatsapp client: %w", err)
	}
	if !b.client.IsLoggedIn() && b.client.Store.ID == nil {
		// No session, need to scan QR
		qrChan, err := b.client.GetQRChannel(context.Background())
		if err != nil {
			return fmt.Errorf("failed to get QR channel: %w", err)
		}
		// Reconnect to trigger QR events
		b.client.Disconnect()
		if err = b.client.Connect(); err != nil {
			return fmt.Errorf("failed to connect after getting QR channel: %w", err)
		}
		go b.handleQR(qrChan) // Handle QR in a separate goroutine
		log.Println("Scan the QR code with WhatsApp to log in.")
	}
	return nil
}

// Ensure client is running and connected
func (b *Bot) EnsureConnected() error {
    if !b.client.IsConnected() {
        log.Println("WhatsApp client not connected, attempting to connect...")
        if err := b.client.Connect(); err != nil {
            return fmt.Errorf("failed to connect WhatsApp client: %w", err)
        }
    }
    if !b.client.IsLoggedIn() {
		// This part might need more robust handling, potentially triggering QR if store.ID is nil
        log.Println("WhatsApp client connected but not logged in.")
		// If there's no device ID, it implies a new login is needed via QR
		if  b.client.Store.ID == nil {
			log.Println("No previous session found. Please scan the QR code.")
			// Trigger QR pairing process
			qrChan, _ := b.client.GetQRChannel(context.Background())
			// It's important to call Connect() again to make the QR channel work after GetQRChannel
			b.client.Disconnect()
			err := b.client.Connect()
			if err != nil {
				return fmt.Errorf("failed to reconnect for QR: %w", err)
			}
			go b.handleQR(qrChan)
			return fmt.Errorf("not logged in, QR process started")
		}
		// If there is a device ID, it might be a session issue or temporary disconnection
		return fmt.Errorf("not logged in, but session exists. May need to re-authenticate or wait.")
    }
    return nil
}
