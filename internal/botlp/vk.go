package botlp

import (
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

// VKChat carries the bridge over the VK Bot API
// (https://dev.vk.com/ru/api/bot-long-poll/getting-started). Frames ride
// as message texts in one conversation (peer_id / chat), delivery is the
// group long-poll stream.
//
// Both sides of the transport must be separate bots in the same
// conversation, because a VK bot never receives its own messages: give
// the client bot A's token and the relay bot B's token, enable bot-to-bot
// messages in both community settings and keep the peer id the same.
// Against the generic contract nothing else changes: the client sends
// into the session room and reads the reply room.
type VKChat struct {
	// Base is the API root (default https://api.vk.com/method/).
	Base string
	// Token is the community access token of THIS side's bot.
	Token string
	// PeerID is the conversation the frames are posted to.
	PeerID int64
	// APIVersion pins the method version (default 5.199).
	APIVersion string
	// HTTP customises the client (nil → sane defaults).
	HTTP *http.Client

	mu      sync.Mutex
	lpSrv   string
	lpKey   string
	lpTS    uint64
	lpReady bool
}

// NewVKChat validates the config; peerID is the conversation id
// (peer_id, 2000000000+X for chats).
func NewVKChat(base, token, peerID string) (*VKChat, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("botlp: vk token required")
	}
	id, err := chatID(peerID)
	if err != nil {
		return nil, fmt.Errorf("botlp: vk: %w", err)
	}
	if base == "" {
		base = "https://api.vk.com/method/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &VKChat{
		Base:       base,
		Token:      token,
		PeerID:     id,
		APIVersion: "5.199",
		HTTP:       &http.Client{Timeout: 90 * time.Second},
	}, nil
}

type vkError struct {
	Error struct {
		Code int    `json:"error_code"`
		Msg  string `json:"error_msg"`
	} `json:"error"`
}

func (v *VKChat) method(ctx context.Context, name string, params url.Values, out any) error {
	params = params.Clone()
	params.Set("access_token", v.Token)
	if v.APIVersion != "" {
		params.Set("v", v.APIVersion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Base+name, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return v.do(req, out)
}

func (v *VKChat) do(req *http.Request, out any) error {
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("botlp: vk http %d: %s", resp.StatusCode, truncate(body))
	}
	var ve vkError
	if json.Unmarshal(body, &ve) == nil && ve.Error.Code != 0 {
		return fmt.Errorf("botlp: vk error %d: %s", ve.Error.Code, ve.Error.Msg)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("botlp: vk reply: %w", err)
		}
	}
	return nil
}

// SendText posts one message into the conversation.
func (v *VKChat) SendText(ctx context.Context, text string) error {
	q := url.Values{}
	q.Set("peer_id", fmt.Sprint(v.PeerID))
	q.Set("random_id", fmt.Sprint(time.Now().UnixNano()))
	q.Set("message", text)
	var out json.RawMessage
	return v.method(ctx, "messages.send", q, &out)
}

type vkLPServer struct {
	Response struct {
		Server string `json:"server"`
		Key    string `json:"key"`
		TS     uint64 `json:"ts"`
	} `json:"response"`
}

type vkPoll struct {
	TS      uint64 `json:"ts"`
	Updates []struct {
		Type   string `json:"type"`
		Object struct {
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"object"`
	} `json:"updates"`
}

// PollTexts long-polls the group stream and returns every new message
// text (the bridge filters by tag itself).
func (v *VKChat) PollTexts(ctx context.Context, wait time.Duration) (uint64, []string, error) {
	wait = clampDur(wait, 1*time.Second, 60*time.Second)
	v.mu.Lock()
	if !v.lpReady {
		v.mu.Unlock()
		if err := v.refreshLP(ctx); err != nil {
			return 0, nil, err
		}
	} else {
		v.mu.Unlock()
	}
	v.mu.Lock()
	srv, key, ts := v.lpSrv, v.lpKey, v.lpTS
	v.mu.Unlock()

	q := url.Values{}
	q.Set("act", "a_check")
	q.Set("key", key)
	q.Set("ts", fmt.Sprint(ts))
	q.Set("wait", fmt.Sprint(int(wait.Seconds())))
	q.Set("mode", "2")
	q.Set("version", "3")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv+"?"+q.Encode(), nil)
	if err != nil {
		return ts, nil, err
	}
	var poll vkPoll
	if err := v.do(req, &poll); err != nil {
		return ts, nil, err
	}
	v.mu.Lock()
	if poll.TS > 0 {
		v.lpTS = poll.TS
	}
	v.mu.Unlock()
	texts := make([]string, 0, len(poll.Updates))
	for _, u := range poll.Updates {
		if u.Type == "message_new" && u.Object.Message.Text != "" {
			texts = append(texts, u.Object.Message.Text)
		}
	}
	return poll.TS, texts, nil
}

func (v *VKChat) refreshLP(ctx context.Context) error {
	var lp vkLPServer
	if err := v.method(ctx, "groups.getLongPollServer", url.Values{}, &lp); err != nil {
		return fmt.Errorf("botlp: vk long-poll server: %w", err)
	}
	if lp.Response.Server == "" || lp.Response.Key == "" {
		return errors.New("botlp: vk long-poll server: empty reply")
	}
	v.mu.Lock()
	v.lpSrv = lp.Response.Server
	v.lpKey = lp.Response.Key
	v.lpTS = lp.Response.TS
	v.lpReady = true
	v.mu.Unlock()
	return nil
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
