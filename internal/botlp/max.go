package botlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// MaxChat carries the bridge over the Max Bot API
// (https://dev.max.ru — the TamTam-style /updates marker stream). Frames
// ride as message texts in one chat; delivery is the marker long-poll.
//
// As with VK, both sides must be separate bots in the same chat: a bot
// does not receive its own messages. Give the client and the relay
// different bot tokens and keep the chat id the same.
type MaxChat struct {
	// Base is the API root (default https://botapi.max.ru).
	Base string
	// Token is the bot access token of THIS side.
	Token string
	// ChatID is the conversation the frames are posted to.
	ChatID int64
	// HTTP customises the client (nil → sane defaults).
	HTTP *http.Client

	mu     sync.Mutex
	marker uint64
	marked bool
}

// NewMaxChat validates the config; chatID is the conversation id.
func NewMaxChat(base, token, chat string) (*MaxChat, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("botlp: max token required")
	}
	id, err := chatID(chat)
	if err != nil {
		return nil, fmt.Errorf("botlp: max: %w", err)
	}
	if base == "" {
		base = "https://botapi.max.ru"
	}
	base = strings.TrimSuffix(base, "/")
	return &MaxChat{
		Base:   base,
		Token:  token,
		ChatID: id,
		HTTP:   &http.Client{Timeout: 90 * time.Second},
	}, nil
}

func (m *MaxChat) do(req *http.Request, out any) error {
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("botlp: max http %d: %s", resp.StatusCode, truncate(body))
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("botlp: max reply: %w", err)
		}
	}
	return nil
}

// SendText posts one message into the chat.
func (m *MaxChat) SendText(ctx context.Context, text string) error {
	q := url.Values{}
	q.Set("chat_id", fmt.Sprint(m.ChatID))
	q.Set("access_token", m.Token)
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.Base+"/messages?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var out json.RawMessage
	return m.do(req, &out)
}

type maxUpdates struct {
	// Marker comes back as a number or a string depending on the API
	// version; json.Number covers both.
	Marker  json.Number `json:"marker"`
	Updates []struct {
		UpdateType string `json:"update_type"`
		Payload    struct {
			Message struct {
				Recipient struct {
					ChatID int64 `json:"chat_id"`
				} `json:"recipient"`
				Body struct {
					Text string `json:"text"`
				} `json:"body"`
			} `json:"message"`
		} `json:"payload"`
	} `json:"updates"`
}

// PollTexts long-polls the updates stream and returns every new message
// text (the bridge filters by tag itself).
func (m *MaxChat) PollTexts(ctx context.Context, wait time.Duration) (uint64, []string, error) {
	wait = clampDur(wait, 1*time.Second, 60*time.Second)
	m.mu.Lock()
	marker := m.marker
	marked := m.marked
	m.mu.Unlock()

	q := url.Values{}
	q.Set("wait", fmt.Sprint(int(wait.Seconds())))
	q.Set("types", "message_created")
	q.Set("access_token", m.Token)
	if marked {
		q.Set("marker", fmt.Sprint(marker))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Base+"/updates?"+q.Encode(), nil)
	if err != nil {
		return marker, nil, err
	}
	var up maxUpdates
	if err := m.do(req, &up); err != nil {
		return marker, nil, err
	}
	newMarker := marker
	if up.Marker != "" {
		if v, perr := up.Marker.Int64(); perr == nil && v >= 0 {
			newMarker = uint64(v)
		}
	}
	m.mu.Lock()
	m.marker = newMarker
	m.marked = true
	m.mu.Unlock()

	texts := make([]string, 0, len(up.Updates))
	for _, u := range up.Updates {
		if u.UpdateType == "message_created" && u.Payload.Message.Body.Text != "" {
			texts = append(texts, u.Payload.Message.Body.Text)
		}
	}
	return newMarker, texts, nil
}
