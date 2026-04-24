package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelegramClient handles sending messages to a Telegram chat.
type TelegramClient struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewTelegramClient creates a new Telegram client.
func NewTelegramClient(token, chatID string) *TelegramClient {
	return &TelegramClient{
		botToken: token,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// SendMessage sends a text message to the configured chat.
func (t *TelegramClient) SendMessage(text string) error {
	if t.botToken == "" || t.chatID == "" {
		return nil
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	payload := map[string]string{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: failed to marshal payload: %w", err)
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("telegram: failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: API returned status %d", resp.StatusCode)
	}

	return nil
}
